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
    public static byte[] Rc2DecryptLegacyRecord(
        string modulePath, string tokenLabel, string keyLabel, byte[] iv, byte[] ciphertext,
        Pkcs11LibraryOptions? options = null)
    {
        #region Rc2DecryptLegacyRecord
        // A record encrypted with RC2-CBC, under a key that is still on the token. Few modules still
        // implement RC2. NSS's softoken does: it needs module parameters to load, and its crypto token
        // ("NSS Generic Crypto Services") takes no login, which is the token this example is written for.

        // 1. Load the module, with the options it needs (for NSS, Pkcs11LibraryOptions.ModuleParameters).
        //    The module path, token label and options come from configuration.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath, options);

        // 2. Open a session without a login: the token takes none. On a token that does (CKF_LOGIN_REQUIRED),
        //    log in instead, with library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin) and the PIN from
        //    your secret store, as on the other pages; without the login its private objects stay hidden.
        using Pkcs11Session session = library.OpenSessionWithoutLogin(tokenLabel);

        // 3. Open the RC2 key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key legacyKey = session.OpenKey(keyLabel);

        // 4. Decrypt, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11005 // RC2Pkcs11: reading a legacy RC2 record
            using var rc2 = new RC2Pkcs11(legacyKey);
#pragma warning restore KLPKCS11005
            return rc2.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        // 5. The using declarations dispose the key handle (the key itself stays on the token), the
        //    session and the library, in reverse order.
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
