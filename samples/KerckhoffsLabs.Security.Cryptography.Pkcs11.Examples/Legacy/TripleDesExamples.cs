using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/triple-des.md: reading a Triple-DES archive.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class TripleDesExamples
{
    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/triple-des.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
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
}
