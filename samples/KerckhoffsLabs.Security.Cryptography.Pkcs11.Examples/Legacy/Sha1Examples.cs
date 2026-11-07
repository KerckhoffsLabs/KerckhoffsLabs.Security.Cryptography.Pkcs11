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
    public static byte[] Sha1ForLegacyProtocol(string modulePath, string tokenLabel, byte[] data)
    {
        #region Sha1ForLegacyProtocol
        // A protocol that still names its records by SHA-1: an identifier, not an integrity check.

        // 1. Load the module (its path from configuration) and open a session on the token. Hashing
        //    uses no key, so no login: a public session will do. Where a token wants a login for every
        //    operation, open it with OpenSessionWithPin, as on the key pages.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithoutLogin(tokenLabel);

        // 2. Hash, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11002 // SHA1Pkcs11: an identifier a legacy protocol requires
            using var sha1 = new SHA1Pkcs11(session);
#pragma warning restore KLPKCS11002
            return sha1.ComputeHash(data);
        }
        // 3. The using declarations close the session, then the library.
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
