using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
    public static byte[] DesDecryptLegacyRecord(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] iv, byte[] ciphertext)
    {
        #region DesDecryptLegacyRecord
        // A record encrypted with single DES-CBC, under a key that is still on the token. Decrypt it,
        // then re-encrypt what you keep with AES-GCM.

        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the DES key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key legacyKey = session.OpenKey(keyLabel);

        // 3. Decrypt, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11003 // DESPkcs11: reading a legacy single-DES record
            using var des = new DESPkcs11(legacyKey);
#pragma warning restore KLPKCS11003
            return des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        // 4. The using declarations dispose the key handle (the key itself stays on the token), the
        //    session and the library, in reverse order.
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
