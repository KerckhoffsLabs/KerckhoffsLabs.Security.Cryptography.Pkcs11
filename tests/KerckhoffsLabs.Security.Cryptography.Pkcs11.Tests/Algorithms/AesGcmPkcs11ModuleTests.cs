using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <see cref="AesGcmPkcs11"/> against a module whose output is not the length AES-GCM gives: through the
/// PKCS#11 v3.0 message API (output as long as the input) and through v2.40 single-part
/// <c>C_Encrypt</c>/<c>C_Decrypt</c> (the tag appended to, or taken off, the ciphertext). The adapter refuses
/// the output rather than copy part of it, or past it, into the caller's buffers, which keep what they held.
/// Each module is an identity cipher, so at the right length the call succeeds and only the length is under test.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AesGcmPkcs11ModuleTests
{
    private const int TagSize = 16;
    private const byte Untouched = 0xA5;
    private static readonly byte[] Nonce = new byte[12];
    private static readonly byte[] Payload = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];

    public static TheoryData<int> WrongLengths => [-1, 1];

    [Fact]
    public void SinglePart_RightLength_RoundTrips() => AssertRoundTrips(new SinglePartModule());

    [Fact]
    public void MessageApi_RightLength_RoundTrips() => AssertRoundTrips(new MessageModule());

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void SinglePart_Encrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertEncryptRefused(new SinglePartModule { Delta = delta }, "AES-GCM encrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void MessageApi_Encrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertEncryptRefused(new MessageModule { Delta = delta }, "AES-GCM message encrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void SinglePart_Decrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertDecryptRefused(new SinglePartModule { Delta = delta }, "AES-GCM decrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void MessageApi_Decrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertDecryptRefused(new MessageModule { Delta = delta }, "AES-GCM message decrypt returned");

    private static void AssertRoundTrips(SinglePartModule module)
    {
        using (module)
        {
            WithAdapter(module, aesGcm =>
            {
                byte[] ciphertext = new byte[Payload.Length];
                byte[] tag = new byte[TagSize];
                aesGcm.Encrypt(Nonce, Payload, ciphertext, tag);
                Assert.Equal(Payload, ciphertext);

                byte[] plaintext = new byte[Payload.Length];
                aesGcm.Decrypt(Nonce, ciphertext, tag, plaintext);
                Assert.Equal(Payload, plaintext);
            });
        }
    }

    private static void AssertEncryptRefused(SinglePartModule module, string message)
    {
        using (module)
        {
            WithAdapter(module, aesGcm =>
            {
                byte[] ciphertext = Filled(Payload.Length);
                byte[] tag = Filled(TagSize);
                var ex = Assert.Throws<InvalidOperationException>(() =>
                    aesGcm.Encrypt(Nonce, Payload, ciphertext, tag));
                Assert.StartsWith(message, ex.Message, StringComparison.Ordinal);
                Assert.Equal(Filled(Payload.Length), ciphertext);
                Assert.Equal(Filled(TagSize), tag);
            });
        }
    }

    private static void AssertDecryptRefused(SinglePartModule module, string message)
    {
        using (module)
        {
            WithAdapter(module, aesGcm =>
            {
                byte[] plaintext = Filled(Payload.Length);
                var ex = Assert.Throws<InvalidOperationException>(() =>
                    aesGcm.Decrypt(Nonce, Payload, new byte[TagSize], plaintext));
                Assert.StartsWith(message, ex.Message, StringComparison.Ordinal);
                Assert.Equal(Filled(Payload.Length), plaintext);
            });
        }
    }

    private static byte[] Filled(int length)
    {
        byte[] buffer = new byte[length];
        buffer.AsSpan().Fill(Untouched);
        return buffer;
    }

    private static void WithAdapter(SinglePartModule module, Action<AesGcmPkcs11> body)
    {
        using Pkcs11Library library = module.Load();
        LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1);
        using var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core);
        using var key = new Pkcs11Key(session, new ObjectHandle(1), ObjectHandle.Invalid, CKK.CKK_AES, "aes", []);
        using var aesGcm = new AesGcmPkcs11(key, TagSize);
        body(aesGcm);
    }

    /// <summary>
    /// A v2.40 module: <c>C_Encrypt</c> copies the plaintext and appends a zero tag, <c>C_Decrypt</c> drops
    /// the tag, each giving <see cref="Delta"/> bytes more (or fewer) than that.
    /// </summary>
    private class SinglePartModule : FakeModule
    {
        public int Delta { get; init; }

        protected override bool ReleasedByFinalize => true;

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
            => Transform(data, data.Length + TagSize + Delta, encryptedData, ref encryptedDataLen);

        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
            => Transform(encryptedData, encryptedData.Length - TagSize + Delta, data, ref dataLen);

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
    /// The same module with the v3.0 message API, which makes the library use it: each message's output is
    /// its input, <see cref="SinglePartModule.Delta"/> bytes longer or shorter. Implementing a v3.0 function
    /// makes the fake hand out a v3.x interface table.
    /// </summary>
    private sealed class MessageModule : SinglePartModule
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
}
