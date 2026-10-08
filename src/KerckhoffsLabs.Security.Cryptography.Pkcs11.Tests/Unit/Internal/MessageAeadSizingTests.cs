using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A message-based GCM, CCM or ChaCha20-Poly1305 keeps its tag in the per-message parameter, so each message's
/// output is exactly as long as its input. It is sized that way, in one call, with no length query (which some
/// tokens answer by running the whole AEAD). A module whose output is longer anyway is answered at the length
/// it reports.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class MessageAeadSizingTests
{
    private static readonly byte[] Payload = [.. Enumerable.Range(0, 48).Select(i => (byte)i)];

    [Fact]
    public void MessageEncrypt_MakesOneCall_AndReturnsTheCiphertext()
    {
        using var module = new MessageModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] ciphertext = session.MessageEncrypt(Gcm(), new ObjectHandle(1), CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16), [0xAD], Payload);

        Assert.Equal(Payload, ciphertext);
        Assert.Equal(1, module.CallCount("C_EncryptMessage"));
    }

    [Fact]
    public void MessageDecrypt_MakesOneCall_AndReturnsThePlaintext()
    {
        using var module = new MessageModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] plaintext = session.MessageDecrypt(Gcm(), new ObjectHandle(1), CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]), [0xAD], Payload);

        Assert.Equal(Payload, plaintext);
        Assert.Equal(1, module.CallCount("C_DecryptMessage"));
    }

    // An empty message is a real one: it is encrypted, in one call, not mistaken for a length query.
    [Fact]
    public void MessageEncrypt_OfAnEmptyMessage_MakesOneCall()
    {
        using var module = new MessageModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] ciphertext = session.MessageEncrypt(Gcm(), new ObjectHandle(1), CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16), [0xAD], []);

        Assert.Empty(ciphertext);
        Assert.Equal(1, module.CallCount("C_EncryptMessage"));
        Assert.False(module.SawALengthQuery);
    }

    [Fact]
    public void MessageEncrypt_LongerThanItsInput_IsFilledAtTheReportedLength()
    {
        using var module = new MessageModule { Expands = 16 };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] ciphertext = session.MessageEncrypt(Gcm(), new ObjectHandle(1), CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16), [0xAD], Payload);

        Assert.Equal(Payload.Length + 16, ciphertext.Length);
        Assert.Equal(2, module.CallCount("C_EncryptMessage"));
    }

    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM);

    /// <summary>An identity AEAD whose output is its input, plus <see cref="Expands"/> bytes.</summary>
    private sealed class MessageModule : FakeModule
    {
        public int Expands { get; init; }
        public bool SawALengthQuery { get; private set; }

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_MessageEncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageEncryptFinal(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen)
            => Transform(plaintext, ciphertext, ref ciphertextLen);

        protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen)
            => Transform(ciphertext, plaintext, ref plaintextLen);

        private CKR Transform(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            int produced = input.Length + Expands;
            length = (NativeCULong)(ulong)produced;
            if (output.IsNull)
            {
                SawALengthQuery = true;
                return CKR.CKR_OK;
            }
            if (output.Span.Length < produced)
                return CKR.CKR_BUFFER_TOO_SMALL;
            input.CopyTo(output.Span);
            return CKR.CKR_OK;
        }
    }
}
