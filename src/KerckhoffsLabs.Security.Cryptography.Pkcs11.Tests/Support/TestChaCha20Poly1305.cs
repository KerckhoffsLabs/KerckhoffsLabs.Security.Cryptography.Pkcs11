using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Test-only raw-<see cref="ObjectHandle"/> ChaCha20-Poly1305 round-trip helper. The shipping API is
/// <c>ChaCha20Poly1305Pkcs11</c> (over <c>Pkcs11Key</c>); only the KAT needs a quick handle-based
/// encrypt/decrypt, so the former session-level convenience lives here. 96-bit nonce, combined
/// ciphertext+tag.
/// </summary>
internal static class TestChaCha20Poly1305
{
    public static byte[] Encrypt(Pkcs11Session session, ObjectHandle key,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
    {
        var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        var mech = new Mechanism(CKM.CKM_CHACHA20_POLY1305, p);
        return session.Encrypt(mech, key, plaintext);
    }

    public static byte[] Decrypt(Pkcs11Session session, ObjectHandle key,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> aad = default)
    {
        var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        var mech = new Mechanism(CKM.CKM_CHACHA20_POLY1305, p);
        return session.Decrypt(mech, key, ciphertextAndTag);
    }
}
