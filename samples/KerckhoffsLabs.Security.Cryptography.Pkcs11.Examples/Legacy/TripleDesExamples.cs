using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
    public static byte[] TripleDesDecryptLegacyArchive(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] iv, byte[] ciphertext)
    {
        #region TripleDesDecryptLegacyArchive
        // An archive written years ago with 3DES-CBC, under a key that is still on the token.
        // Decrypt it once, then re-encrypt what you need to keep with AES-GCM.

        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the 3DES key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key legacyKey = session.OpenKey(keyLabel);

        // 3. Decrypt, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11004 // TripleDESPkcs11: reading a legacy 3DES archive
            using var des3 = new TripleDESPkcs11(legacyKey);
#pragma warning restore KLPKCS11004
            return des3.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        // 4. The using declarations dispose the key handle (the key itself stays on the token), the
        //    session and the library, in reverse order.
        #endregion
    }

    [SuppressMessage("Security", "S5547:Use a strong cipher algorithm", Justification = "The software counterpart of the legacy decryption the token example runs (docs/examples/triple-des.md).")]
    public static byte[] BclTripleDesDecryptLegacyArchive(byte[] key, byte[] iv, byte[] ciphertext)
    {
        #region BclTripleDesDecryptLegacyArchive
        // The same decryption in software. The key is in your process here, which is what a token avoids:
        // use this only where the 3DES key already lives in software.
        using TripleDES des3 = TripleDES.Create();
        des3.Key = key;
        return des3.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        #endregion
    }
}
