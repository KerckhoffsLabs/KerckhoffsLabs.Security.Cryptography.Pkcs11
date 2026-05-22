using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Test-only raw-<see cref="ObjectHandle"/> AES-GCM round-trip helper. The shipping AES-GCM API is
/// <c>AesGcmPkcs11</c> (over <c>Pkcs11Key</c>); a few low-level tests (KAT, wrap/unwrap, derive)
/// just need a quick encrypt/decrypt against a session handle to confirm a key works, so the old
/// session-level convenience lives here instead of in the production surface. Fixed 96-bit IV,
/// 128-bit tag, ciphertext+tag combined — the PKCS#11 AEAD output format.
/// </summary>
internal static class TestAesGcm
{
    public static byte[] Encrypt(Pkcs11Session session, ObjectHandle key,
        ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
    {
        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        return session.Encrypt(mech, key, plaintext);
    }

    public static byte[] Decrypt(Pkcs11Session session, ObjectHandle key,
        ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> aad = default)
    {
        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        return session.Decrypt(mech, key, ciphertextAndTag);
    }
}
