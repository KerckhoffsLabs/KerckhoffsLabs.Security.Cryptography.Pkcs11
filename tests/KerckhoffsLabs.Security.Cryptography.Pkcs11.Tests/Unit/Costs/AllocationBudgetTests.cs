using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Policies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Costs;

/// <summary>
/// The managed bytes one call through the public API allocates, at steady state, as a ceiling: through
/// <see cref="Pkcs11Key"/> and <see cref="Pkcs11Session"/>, under the default <see cref="CryptoPolicy.Recommended"/>
/// and with key inspection off. Unlike time, allocation is deterministic, so a fixed budget does not flake.
/// </summary>
/// <remarks>
/// <para>
/// A budget is today's measurement on 64-bit with a little headroom; a 32-bit process allocates less and passes too.
/// The module is allocation-free (every answer is written into the caller's buffers), so the bytes counted are the
/// library's: the result array, the session's leases and the token gate's per-operation record, the mechanism's
/// parameter block, the policy decision, and under <c>Recommended</c> the key-strength read and its request.
/// </para>
/// <para>
/// A budget fails when a change allocates more; a change that allocates less should lower it in the same change.
/// The leases (CP-012), the token gate and the key-strength request (#388's read) are where the next reductions are
/// expected.
/// </para>
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class AllocationBudgetTests
{
    private const int AesKey = 1;
    private const int HmacKey = 2;
    private static readonly byte[] Data = new byte[32];

    // Path; whether the policy inspects keys; budget in bytes. Each comment gives the 64-bit measurement the budget was
    // set from (about 10% headroom, as for the core's 480 B attribute-read budget).
    public static TheoryData<string, bool, int> Budgets => new()
    {
        // The key-strength read under Recommended costs 528 B on either key: its attribute template and result, the
        // KeyStrengthRequest and its `with` copies, and a third lease with its token-gate record.
        { "HMAC-SHA256 sign", true, 1336 },        // 1,208 B
        { "HMAC-SHA256 sign", false, 752 },        // 680 B
        { "AES-GCM encrypt 32 B", true, 1160 },    // 1,048 B
        { "AES-GCM encrypt 32 B", false, 576 },    // 520 B
        // Keyless: the policy reads no key, so both cost the same.
        { "SHA-256 digest", true, 600 },           // 544 B
        { "SHA-256 digest", false, 600 },          // 544 B
        { "GenerateRandom(span) 32 B", true, 104 }, // 88 B
    };

    [Theory]
    [MemberData(nameof(Budgets))]
    public void SteadyState_StaysWithinItsBudget(string path, bool inspectKeys, int budget)
    {
        using var module = new BudgetModule();
        using Pkcs11Library library = module.Load(new Pkcs11LibraryOptions
        {
            Policy = inspectKeys ? CryptoPolicy.Recommended : TestPolicies.RecommendedWithoutKeyInspection,
        });
        using Pkcs11Session session = library.GetSlotList()[0].OpenSession(SessionAccess.ReadOnly);
        using var aes = new Pkcs11Key(session, new ObjectHandle(AesKey), ObjectHandle.Invalid, CKK.CKK_AES, label: null, id: []);
        using var hmac = new Pkcs11Key(session, new ObjectHandle(HmacKey), ObjectHandle.Invalid, CKK.CKK_GENERIC_SECRET, label: null, id: []);
        var gcm = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));
        var hmacSha256 = new Mechanism(CKM.CKM_SHA256_HMAC);
        var sha256 = new Mechanism(CKM.CKM_SHA256);
        byte[] random = new byte[32];

        Action operation = path switch
        {
            "HMAC-SHA256 sign" => () => hmac.Sign(hmacSha256, Data),
            "AES-GCM encrypt 32 B" => () => aes.Encrypt(gcm, Data),
            "SHA-256 digest" => () => session.Digest(sha256, Data),
            "GenerateRandom(span) 32 B" => () => session.GenerateRandom(random),
            _ => throw new ArgumentOutOfRangeException(nameof(path), path, null),
        };
        long allocated = Allocated(operation);

        Assert.True(allocated <= budget,
            $"{path} ({(inspectKeys ? "Recommended" : "key inspection off")}) allocated {allocated} B; the budget is {budget} B.");
    }

    // Bytes the current thread allocates for one call, after two warm-up calls have paid the one-time costs (JIT,
    // tiering, statics, first-use caches).
    private static long Allocated(Action action)
    {
        action();
        action();
        long before = GC.GetAllocatedBytesForCurrentThread();
        action();
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    /// <summary>
    /// One slot whose token holds an AES key (handle 1) and an HMAC key (handle 2), each describing itself as a token
    /// does for the key-strength read (type and length; any other attribute is absent). Operations answer at fixed
    /// lengths: a 32-byte MAC and digest, and the plaintext followed by a 16-byte tag. Nothing here allocates.
    /// </summary>
    private sealed class BudgetModule : FakeModule
    {
        private const int MacLength = 32;
        private const int DigestLength = 32;
        private const int TagLength = 16;

        protected override bool ReleasedByFinalize => true;

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            if (!slotList.IsNull)
            {
                if (slotList.Span.Length < 1)
                {
                    count = (NativeCULong)1;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                slotList.Span[0] = (NativeCULong)0;
            }
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            session = NewSessionHandle();
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_OK;
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            Span<byte> value = stackalloc byte[sizeof(ulong)];
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                ulong? answer = (CKA)(ulong)template[i].type switch
                {
                    CKA.CKA_KEY_TYPE => (ulong)((ulong)objectHandle == AesKey ? CKK.CKK_AES : CKK.CKK_GENERIC_SECRET),
                    CKA.CKA_VALUE_LEN => 32,
                    _ => null,
                };
                if (answer is not { } number)
                {
                    template[i].valueLen = NativeCULong.MaxValue;
                    rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }
                // A CK_ULONG at the platform's width: 4 bytes on Windows, 8 elsewhere.
                int size = System.Runtime.CompilerServices.Unsafe.SizeOf<NativeCULong>();
                if (size == sizeof(uint))
                    BitConverter.TryWriteBytes(value, (uint)number);
                else
                    BitConverter.TryWriteBytes(value, number);
                CKR answered = AnswerAttribute(ref template[i], value[..size]);
                if (answered != CKR.CKR_OK)
                    rv = answered;
            }
            return rv;
        }

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => FixedLength(MacLength, signature, ref signatureLen);

        protected override CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> digest, ref NativeCULong digestLen)
            => FixedLength(DigestLength, digest, ref digestLen);

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        {
            int length = data.Length + TagLength;
            if (!encryptedData.IsNull)
            {
                if (encryptedData.Span.Length < length)
                {
                    encryptedDataLen = (NativeCULong)(ulong)length;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                data.CopyTo(encryptedData.Span);
            }
            encryptedDataLen = (NativeCULong)(ulong)length;
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            randomData.Fill(0x5A);
            return CKR.CKR_OK;
        }

        private static CKR FixedLength(int length, NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            if (!output.IsNull)
            {
                if (output.Span.Length < length)
                {
                    outputLen = (NativeCULong)(ulong)length;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                output.Span[..length].Fill(0xA5);
            }
            outputLen = (NativeCULong)(ulong)length;
            return CKR.CKR_OK;
        }
    }
}
