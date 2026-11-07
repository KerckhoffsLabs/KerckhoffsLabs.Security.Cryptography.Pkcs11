using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/rc2.md: reading an RC2 record.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class Rc2Examples
{
    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/rc2.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
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

    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "The software counterpart of the legacy decryption the token example runs (docs/examples/rc2.md).")]
    public static byte[] BclRc2DecryptLegacyRecord(byte[] key, byte[] iv, byte[] ciphertext)
    {
        #region BclRc2DecryptLegacyRecord
        // The same decryption in software. The key is in your process here, which is what a token avoids:
        // use this only where the RC2 key already lives in software.
        using RC2 rc2 = RC2.Create();
        rc2.Key = key;
        return rc2.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        #endregion
    }
}
