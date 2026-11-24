using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Policies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

/// <summary>
/// A v2.40 AEAD module whose cipher is the identity: <c>C_Encrypt</c> copies the plaintext and appends a zero
/// tag of <see cref="TagLength"/> bytes, <c>C_Decrypt</c> drops the tag, each giving <see cref="Delta"/> bytes
/// more (or fewer) than that. At <see cref="Delta"/> 0 the AEAD adapters round-trip over it, so only the
/// output's length is under test.
/// </summary>
internal class IdentityAeadModule : FakeModule
{
    public int Delta { get; init; }

    public int TagLength { get; init; } = 16;

    protected override bool ReleasedByFinalize => true;

    /// <summary>A key handle 1 of <paramref name="keyType"/> over this module, for an adapter to wrap.</summary>
    public void WithKey(CKK keyType, Action<Pkcs11Key> body)
    {
        using Pkcs11Library library = Load();
        LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1, policy: TestPolicies.RecommendedWithoutKeyInspection);
        using var session = new Pkcs11Session(library, new Pkcs11Slot(library, slotId: 1), core);
        using var key = new Pkcs11Key(session, new ObjectHandle(1), ObjectHandle.Invalid, keyType, "aead", []);
        body(key);
    }

    protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

    protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

    protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        => Transform(data, data.Length + TagLength + Delta, encryptedData, ref encryptedDataLen);

    protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

    protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
        => Transform(encryptedData, encryptedData.Length - TagLength + Delta, data, ref dataLen);

    // Writes the first produced bytes of input (zeros past its end), after answering a length query or a
    // buffer too small for them.
    protected static CKR Transform(ReadOnlySpan<byte> input, int produced, NativeBuffer<byte> output, ref NativeCULong length)
    {
        length = (NativeCULong)(ulong)produced;
        if (output.IsNull)
            return CKR.CKR_OK;
        if (output.Span.Length < produced)
            return CKR.CKR_BUFFER_TOO_SMALL;
        Span<byte> destination = output.Span[..produced];
        destination.Clear();
        input[..Math.Min(input.Length, produced)].CopyTo(destination);
        return CKR.CKR_OK;
    }
}

/// <summary>
/// <see cref="IdentityAeadModule"/> with the v3.0 message API, which makes the library use it: each message's
/// output is its input, <see cref="IdentityAeadModule.Delta"/> bytes longer or shorter. Implementing a v3.0
/// function makes the fake hand out a v3.x interface table.
/// </summary>
internal sealed class IdentityAeadMessageModule : IdentityAeadModule
{
    protected override CKR C_MessageEncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

    protected override CKR C_MessageEncryptFinal(NativeCULong session) => CKR.CKR_OK;

    protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

    protected override CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_OK;

    protected override CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen)
        => Transform(plaintext, plaintext.Length + Delta, ciphertext, ref ciphertextLen);

    protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen)
        => Transform(ciphertext, ciphertext.Length + Delta, plaintext, ref plaintextLen);
}
