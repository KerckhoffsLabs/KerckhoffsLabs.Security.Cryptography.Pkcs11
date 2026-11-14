using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/dsa.md: verifying an old DSA signature.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class DsaExamples
{
    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/dsa.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static bool DsaVerifyLegacySignature(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data, byte[] signature)
    {
        #region DsaVerifyLegacySignature
        // Verifying a signature a DSA key made in the past. Verification only: sign anything new with
        // ECDSA, ML-DSA or RSA-PSS.

        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();

        // 2. Open the DSA key that is already on the token, by its CKA_LABEL (OpenKey(id) finds it by
        //    CKA_ID instead). It throws if no key, or more than one, matches.
        using Pkcs11Key legacyKey = session.OpenKey(keyLabel);

        // 3. Verify, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11006 // DSAPkcs11: verifying a legacy DSA signature
            using var dsa = new DSAPkcs11(legacyKey);
#pragma warning restore KLPKCS11006
            return dsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        // 4. The using declarations dispose the key handle (the key itself stays on the token), the
        //    session and the library, in reverse order.
        #endregion
    }

    public static bool BclDsaVerifyLegacySignature(DSAParameters publicKey, byte[] data, byte[] signature)
    {
        #region BclDsaVerifyLegacySignature
        // In software: the BCL's DSA from the key's public parameters, with no policy to lift. Not on
        // macOS, whose DSA takes only 1024-bit keys.
        using DSA dsa = DSA.Create(publicKey);
        return dsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        #endregion
    }
}
