using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Pins what one single-part operation costs, in the two currencies that are deterministic: native
/// calls into the module, and managed bytes allocated per byte of input. Wall-clock time is not
/// measured; it is noise on shared runners and is dominated by the token anyway.
/// </summary>
/// <remarks>
/// <para>
/// A native call is a round trip on a network HSM, so a change that adds one is a regression even
/// when every functional test still passes, and a change that removes one should prove it here.
/// </para>
/// <para>
/// Allocation is measured as a slope: the bytes allocated for a 2 MiB input minus those for a 1 MiB
/// input, per input byte. The fixed per-call overhead cancels out, so the slope counts how many
/// input-sized buffers the operation creates, to within half a buffer. The bounds are today's numbers;
/// an extra copy of the input fails the test, and removing one should lower the bound in the same change.
/// </para>
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class OperationCostGuardTests
{
    private const int SmallInput = 1 << 20;
    private const int LargeInput = 2 << 20;

    [Fact]
    public void Sign_MakesALengthProbeAndOneSignCall()
    {
        using var module = new EchoModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(1), "data"u8);

        Assert.Equal(1, module.CallCount("C_SignInit"));
        Assert.Equal(2, module.CallCount("C_Sign"));
    }

    [Fact]
    public void Digest_MakesALengthProbeAndOneDigestCall()
    {
        using var module = new EchoModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(1, module.CallCount("C_DigestInit"));
        Assert.Equal(2, module.CallCount("C_Digest"));
    }

    [Fact]
    public void Encrypt_SizesTheOutputUpFront_AndMakesOneEncryptCall()
    {
        using var module = new EchoModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        session.Encrypt(Gcm(), new ObjectHandle(1), "data"u8);

        Assert.Equal(1, module.CallCount("C_EncryptInit"));
        Assert.Equal(1, module.CallCount("C_Encrypt"));
    }

    // The caller's span is pinned and handed to the module as is: no copy of the input.
    [Fact]
    public void Sign_AllocatesNoInputSizedBuffer()
        => AssertAllocationSlope(maxBuffersPerInput: 0, (session, data) =>
            session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(1), data));

    // As for Sign.
    [Fact]
    public void Digest_AllocatesNoInputSizedBuffer()
        => AssertAllocationSlope(maxBuffersPerInput: 0, (session, data) =>
            session.Digest(new Mechanism(CKM.CKM_SHA256), data));

    // The ciphertext itself, and no copy of the input.
    [Fact]
    public void Encrypt_AllocatesOneInputSizedBuffer()
        => AssertAllocationSlope(maxBuffersPerInput: 1, (session, data) =>
            session.Encrypt(Gcm(), new ObjectHandle(1), data));

    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));

    private delegate void Operation(Pkcs11Session session, ReadOnlySpan<byte> data);

    private static void AssertAllocationSlope(int maxBuffersPerInput, Operation operation)
    {
        using var module = new EchoModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());
        byte[] small = new byte[SmallInput];
        byte[] large = new byte[LargeInput];

        long smallBytes = Allocated(() => operation(session, small));
        long largeBytes = Allocated(() => operation(session, large));
        double buffersPerInput = (double)(largeBytes - smallBytes) / (LargeInput - SmallInput);

        // Half a buffer of slack: an extra copy adds a whole one, while the per-call overhead that does
        // not quite cancel out between the two runs (seen at 0.03 on win-x86) stays far below it.
        Assert.True(buffersPerInput < maxBuffersPerInput + 0.5,
            $"{buffersPerInput:F2} input-sized buffers per operation (allocated {smallBytes} B for 1 MiB, {largeBytes} B for 2 MiB); expected at most {maxBuffersPerInput}.");
    }

    // Bytes the current thread allocates for one call, after a warm-up call has paid the one-time
    // costs (JIT, statics, first-use caches).
    private static long Allocated(Action action)
    {
        action();
        long before = GC.GetAllocatedBytesForCurrentThread();
        action();
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    /// <summary>
    /// A module whose operations need no keys: fixed-size signatures and digests, and an encryption
    /// that returns the plaintext followed by a 16-byte tag, the shape of AES-GCM's output.
    /// </summary>
    private sealed class EchoModule : FakeModule
    {
        private const int SignatureLength = 64;
        private const int DigestLength = 32;
        private const int TagLength = 16;

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_OK;
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => FixedLength(SignatureLength, signature, ref signatureLen);

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
