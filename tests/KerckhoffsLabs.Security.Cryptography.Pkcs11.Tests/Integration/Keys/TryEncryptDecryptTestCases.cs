using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic tests of <see cref="Pkcs11Key.TryEncrypt"/> and <see cref="Pkcs11Key.TryDecrypt"/>:
/// <see langword="false"/> only when the result does not fit, 0 written and nothing left in the
/// destination then, and the operation finished either way. Decrypting AES-GCM into a destination of
/// exactly the plaintext's length is the case SoftHSM 2.7 refuses with <c>CKR_BUFFER_TOO_SMALL</c>,
/// so on SoftHSM it runs the pooled-scratch path.
/// </summary>
internal static class TryEncryptDecryptTestCases
{
    private const int TagLength = 16;
    private static readonly byte[] Plaintext = [.. Enumerable.Range(0, 40).Select(i => (byte)i)];

    /// <summary>Runs <paramref name="body"/> with an ephemeral AES-256 key; skips when <paramref name="mechanism"/> is not advertised.</summary>
    public static void WithAesKey(IPkcs11Backend backend, CKM mechanism, Action<Pkcs11Key> body)
    {
        if (!backend.Supports(mechanism))
            Assert.Skip($"Backend does not advertise {mechanism}.");

        using var session = backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"try-{Guid.NewGuid():N}").ValueLen(32).Encrypt().Decrypt().OnToken(false).Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        body(key);
    }

    public static void Assert_Gcm_RoundTrips_IntoExactDestinations(Pkcs11Key key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[Plaintext.Length + TagLength];
        Assert.True(key.TryEncrypt(Gcm(nonce), Plaintext, ciphertext, out int encrypted));
        Assert.Equal(ciphertext.Length, encrypted);

        byte[] plaintext = new byte[Plaintext.Length];
        Assert.True(key.TryDecrypt(Gcm(nonce), ciphertext, plaintext, out int decrypted));
        Assert.Equal(Plaintext.Length, decrypted);
        Assert.Equal(Plaintext, plaintext);

        // Again: after the first call a module that wants an input-sized buffer is known for the slot.
        Array.Clear(plaintext);
        Assert.True(key.TryDecrypt(Gcm(nonce), ciphertext, plaintext, out decrypted));
        Assert.Equal(Plaintext, plaintext.AsSpan(0, decrypted).ToArray());
    }

    public static void Assert_TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing(Pkcs11Key key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = key.Encrypt(Gcm(nonce), Plaintext);
        byte[] destination = new byte[Plaintext.Length - 1];
        destination.AsSpan().Fill(0xA5);

        Assert.False(key.TryDecrypt(Gcm(nonce), ciphertext, destination, out int written));

        Assert.Equal(0, written);
        Assert.All(destination, b => Assert.Equal(0, b));
        // The operation was finished: the next one starts cleanly.
        Assert.Equal(Plaintext, key.Decrypt(Gcm(nonce), ciphertext));
    }

    public static void Assert_TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing(Pkcs11Key key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] destination = new byte[Plaintext.Length];
        destination.AsSpan().Fill(0xA5);

        Assert.False(key.TryEncrypt(Gcm(nonce), Plaintext, destination, out int written));

        Assert.Equal(0, written);
        Assert.All(destination, b => Assert.Equal(0, b));
        Assert.Equal(Plaintext.Length + TagLength, key.Encrypt(Gcm(nonce), Plaintext).Length);
    }

    // Destinations larger than the results: the length written is the result's, not the destination's.
    public static void Assert_Gcm_IntoLargerDestinations_WritesTheResultLength(Pkcs11Key key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[Plaintext.Length + TagLength + 32];
        Assert.True(key.TryEncrypt(Gcm(nonce), Plaintext, ciphertext, out int encrypted));
        Assert.Equal(Plaintext.Length + TagLength, encrypted);

        byte[] plaintext = new byte[Plaintext.Length + 32];
        Assert.True(key.TryDecrypt(Gcm(nonce), ciphertext.AsSpan(0, encrypted), plaintext, out int decrypted));
        Assert.Equal(Plaintext, plaintext.AsSpan(0, decrypted).ToArray());
    }

    public static void Assert_OverlappingDestination_Throws(Pkcs11Key key)
    {
        byte[] buffer = new byte[Plaintext.Length + TagLength];
        Plaintext.CopyTo(buffer, 0);

        Assert.Throws<ArgumentException>(() =>
            key.TryEncrypt(Gcm(new byte[12]), buffer.AsSpan(0, Plaintext.Length), buffer, out _));
        Assert.Throws<ArgumentException>(() =>
            key.TryDecrypt(Gcm(new byte[12]), buffer, buffer.AsSpan(8), out _));
    }

    private static Mechanism Gcm(byte[] nonce) => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(nonce, [], tagBits: TagLength * 8));

}
