using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
    public void SinglePart_RightLength_RoundTrips() => AssertRoundTrips(new IdentityAeadModule());

    [Fact]
    public void MessageApi_RightLength_RoundTrips() => AssertRoundTrips(new IdentityAeadMessageModule());

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void SinglePart_Encrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertEncryptRefused(new IdentityAeadModule { Delta = delta }, "AES-GCM encrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void MessageApi_Encrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertEncryptRefused(new IdentityAeadMessageModule { Delta = delta }, "AES-GCM message encrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void SinglePart_Decrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertDecryptRefused(new IdentityAeadModule { Delta = delta }, "AES-GCM decrypt returned");

    [Theory]
    [MemberData(nameof(WrongLengths))]
    public void MessageApi_Decrypt_OutputOfTheWrongLength_Throws(int delta) =>
        AssertDecryptRefused(new IdentityAeadMessageModule { Delta = delta }, "AES-GCM message decrypt returned");

    private static void AssertRoundTrips(IdentityAeadModule module)
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

    private static void AssertEncryptRefused(IdentityAeadModule module, string message)
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

    private static void AssertDecryptRefused(IdentityAeadModule module, string message)
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

    private static void WithAdapter(IdentityAeadModule module, Action<AesGcmPkcs11> body)
        => module.WithKey(CKK.CKK_AES, key =>
        {
            using var aesGcm = new AesGcmPkcs11(key, TagSize);
            body(aesGcm);
        });
}
