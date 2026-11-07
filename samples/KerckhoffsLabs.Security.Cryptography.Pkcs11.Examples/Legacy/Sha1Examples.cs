using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/sha-1.md: SHA-1 as an identifier a legacy protocol requires.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class Sha1Examples
{
    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/sha-1.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
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

    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "The software counterpart of the legacy identifier the token example computes (docs/examples/sha-1.md).")]
    public static byte[] BclSha1(byte[] data)
    {
        #region BclSha1
        // The same identifier in software: no token, so no policy lease.
        byte[] digest = SHA1.HashData(data);
        #endregion
        return digest;
    }
}
