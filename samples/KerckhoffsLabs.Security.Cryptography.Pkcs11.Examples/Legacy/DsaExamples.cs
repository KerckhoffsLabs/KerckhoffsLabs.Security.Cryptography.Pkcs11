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

    public static bool DsaVerifyWithBcl(byte[] data, byte[] signature, DSAParameters publicKey)
    {
        #region DsaVerifyWithBcl
        // Verification needs only the public key, so the BCL's DSA does it off the token, from the token key's
        // ExportParameters(false). Not on macOS, whose DSA takes only 1024-bit keys.
        using DSA verifier = DSA.Create(publicKey);
        return verifier.VerifyData(data, signature, HashAlgorithmName.SHA256);
        #endregion
    }
}
