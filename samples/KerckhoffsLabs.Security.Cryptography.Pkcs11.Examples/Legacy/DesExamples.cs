using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/des.md: reading a single-DES record.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class DesExamples
{
    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/des.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
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

    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "The software counterpart of the legacy decryption the token example runs (docs/examples/des.md).")]
    public static byte[] BclDesDecryptLegacyRecord(byte[] key, byte[] iv, byte[] ciphertext)
    {
        #region BclDesDecryptLegacyRecord
        // The same decryption in software. The key is in your process here, which is what a token avoids:
        // use this only where the DES key already lives in software.
        using DES des = DES.Create();
        des.Key = key;
        return des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        #endregion
    }
}
