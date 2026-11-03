using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/legacy.md: reading and verifying data that legacy algorithms produced. Each example
/// lifts the policy for one scoped operation and suppresses exactly the diagnostic it raises; none
/// produces new legacy data.
/// </summary>
public static class LegacyExamples
{
    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] TripleDesDecryptLegacyArchive(Pkcs11Session session, Pkcs11Key legacyKey, byte[] iv, byte[] ciphertext)
    {
        #region TripleDesDecryptLegacyArchive
        // An archive written years ago with 3DES-CBC, under a key that is still on the token.
        // Decrypt it once, then re-encrypt what you need to keep with AES-GCM.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))   // lifted for this block only
        {
#pragma warning disable KLPKCS11004 // TripleDESPkcs11: reading a legacy 3DES archive
            using var des3 = new TripleDESPkcs11(legacyKey);
#pragma warning restore KLPKCS11004
            return des3.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        #endregion
    }

    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] DesDecryptLegacyRecord(Pkcs11Session session, Pkcs11Key legacyKey, byte[] iv, byte[] ciphertext)
    {
        #region DesDecryptLegacyRecord
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11003 // DESPkcs11: reading a legacy single-DES record
            using var des = new DESPkcs11(legacyKey);
#pragma warning restore KLPKCS11003
            return des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        #endregion
    }

    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] Rc2DecryptLegacyRecord(Pkcs11Session session, Pkcs11Key legacyKey, byte[] iv, byte[] ciphertext)
    {
        #region Rc2DecryptLegacyRecord
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11005 // RC2Pkcs11: reading a legacy RC2 record
            using var rc2 = new RC2Pkcs11(legacyKey);
#pragma warning restore KLPKCS11005
            return rc2.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        #endregion
    }

    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static bool DsaVerifyLegacySignature(Pkcs11Session session, Pkcs11Key legacyKey, byte[] data, byte[] signature)
    {
        #region DsaVerifyLegacySignature
        // Verifying a signature a DSA key made in the past. Verification only: sign anything new with
        // ECDSA, ML-DSA or RSA-PSS.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11006 // DSAPkcs11: verifying a legacy DSA signature
            using var dsa = new DSAPkcs11(legacyKey);
#pragma warning restore KLPKCS11006
            return dsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        #endregion
    }

    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] Md5ChecksumForLegacyProtocol(Pkcs11Session session, byte[] data)
    {
        #region Md5ChecksumForLegacyProtocol
        // A protocol that still names its records by MD5. Never rely on MD5 for integrity: collisions
        // are practical.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11001 // MD5Pkcs11: a non-security checksum a legacy protocol requires
            using var md5 = new MD5Pkcs11(session);
#pragma warning restore KLPKCS11001
            return md5.ComputeHash(data);
        }
        #endregion
    }

    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/legacy.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] Sha1ForLegacyProtocol(Pkcs11Session session, byte[] data)
    {
        #region Sha1ForLegacyProtocol
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11002 // SHA1Pkcs11: an identifier a legacy protocol requires
            using var sha1 = new SHA1Pkcs11(session);
#pragma warning restore KLPKCS11002
            return sha1.ComputeHash(data);
        }
        #endregion
    }
}
