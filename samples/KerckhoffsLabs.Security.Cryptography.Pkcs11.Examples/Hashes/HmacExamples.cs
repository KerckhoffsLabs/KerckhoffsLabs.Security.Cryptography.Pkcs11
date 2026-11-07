using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/hmac.md: HMAC with a token key.</summary>
public static class HmacExamples
{
    public static Pkcs11Key GenerateHmacKey(Pkcs11Session session, string label)
    {
        #region GenerateHmacKey
        // Once, at provisioning: a 256-bit generic secret, allowed to sign (compute) and verify HMACs
        // only, kept on the token under a label.
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label)
            .OnToken()
            .ValueLen(32)
            .Sign()
            .Verify()
            .Build();
        Pkcs11Key key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), template);
        #endregion
        return key;
    }

    public static byte[] HmacSha256(string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data)
    {
        #region HmacSha256
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the HMAC key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key key = session.OpenKey(keyLabel);

        // 3. Compute the MAC on the token.
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);   // an HMAC
        byte[] tag = hmac.ComputeHash(data);
        // 4. The using declarations dispose the adapter, the key handle (the key itself stays on the
        //    token), the session and the library, in reverse order.
        #endregion
        return tag;
    }

    public static byte[] BclHmacSha256(byte[] key, byte[] data)
    {
        #region BclHmacSha256
        using var hmac = new HMACSHA256(key);                  // the key is bytes in your process
        byte[] tag = hmac.ComputeHash(data);
        #endregion
        return tag;
    }
}
