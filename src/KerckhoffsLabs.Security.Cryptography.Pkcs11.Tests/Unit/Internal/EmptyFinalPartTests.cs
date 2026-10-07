using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A multi-part operation whose final part is empty (CTR, or block-aligned data with no padding to strip)
/// must still end. The final is asked for its length, then filled into a zero-length buffer; that buffer
/// has to reach the module as a real address, because a NULL one is another length query (PKCS#11 v3.2
/// §5.2) and leaves the operation active, so the next operation of that kind is refused.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class EmptyFinalPartTests
{
    private static readonly byte[] Payload = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];

    [Fact]
    public void DecryptStream_WithAnEmptyFinalPart_EndsTheOperation()
    {
        using var module = new StreamModule();
        using Pkcs11Library library = module.Load();
        using var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        Assert.Equal(Payload, Decrypt(session));
        Assert.Equal(Payload, Decrypt(session));

        Assert.Equal(2, module.CallCount(nameof(LowLevelPkcs11Library.C_DecryptInit)));
        Assert.Equal(0, module.FinalsLeftActive);
    }

    [Fact]
    public void EncryptStream_WithAnEmptyFinalPart_EndsTheOperation()
    {
        using var module = new StreamModule();
        using Pkcs11Library library = module.Load();
        using var session = new Pkcs11Session(library.LowLevelLibrary!, (ulong)module.OpenSession());

        Assert.Equal(Payload, Encrypt(session));
        Assert.Equal(Payload, Encrypt(session));

        Assert.Equal(2, module.CallCount(nameof(LowLevelPkcs11Library.C_EncryptInit)));
        Assert.Equal(0, module.FinalsLeftActive);
    }

    private static byte[] Decrypt(Pkcs11Session session)
    {
        using var input = new MemoryStream(Payload);
        using var output = new MemoryStream();
        session.Decrypt(Gcm(), new ObjectHandle(1), input, output, 16);
        return output.ToArray();
    }

    private static byte[] Encrypt(Pkcs11Session session)
    {
        using var input = new MemoryStream(Payload);
        using var output = new MemoryStream();
        session.Encrypt(Gcm(), new ObjectHandle(1), input, output, 16);
        return output.ToArray();
    }

    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));

    /// <summary>
    /// An identity cipher whose final part is always empty. The operation ends only on a final that is
    /// handed a buffer; one handed NULL answers the length and leaves the operation active, as the
    /// specification requires, and a second init then fails with <c>CKR_OPERATION_ACTIVE</c>.
    /// </summary>
    private sealed class StreamModule : FakeModule
    {
        private bool _active;

        public int FinalsLeftActive { get; private set; }

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Begin();
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Begin();

        protected override CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Copy(part, encryptedPart, ref encryptedPartLen);

        protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Copy(encryptedPart, part, ref partLen);

        protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
            => Final(lastEncryptedPart, ref lastEncryptedPartLen);

        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
            => Final(lastPart, ref lastPartLen);

        private CKR Begin()
        {
            if (_active)
                return CKR.CKR_OPERATION_ACTIVE;
            _active = true;
            return CKR.CKR_OK;
        }

        private static CKR Copy(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            if (!output.IsNull)
                input.CopyTo(output.Span);
            length = (NativeCULong)(ulong)input.Length;
            return CKR.CKR_OK;
        }

        private CKR Final(NativeBuffer<byte> output, ref NativeCULong length)
        {
            length = (NativeCULong)0;
            if (output.IsNull)
            {
                FinalsLeftActive++;
                return CKR.CKR_OK;
            }
            FinalsLeftActive--;
            _active = false;
            return CKR.CKR_OK;
        }
    }
}
