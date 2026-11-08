using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>
/// docs/examples/md5.md: MD5 as an identifier a legacy protocol requires.
/// Like every legacy example, it lifts the policy for one scoped operation and suppresses exactly
/// the diagnostic it raises; it produces no new legacy data.
/// </summary>
public static class Md5Examples
{
    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "Reads or verifies existing legacy data, which is the point of this example (docs/examples/md5.md); under a scoped AllowInsecure lease, with the [Obsolete] diagnostic suppressed at the line.")]
    public static byte[] Md5ChecksumForLegacyProtocol(string modulePath, string tokenLabel, byte[] data)
    {
        #region Md5ChecksumForLegacyProtocol
        // A protocol that still names its records by MD5. Never rely on MD5 for integrity: collisions
        // are practical.

        // 1. Load the module (its path from configuration) and open a session on the token. Hashing
        //    uses no key, so no login: a public session will do. Where a token wants a login for every
        //    operation, open it with OpenSessionWithPin, as on the key pages.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithoutLogin(tokenLabel);

        // 2. Hash, with the policy lifted for this block only.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11001 // MD5Pkcs11: a non-security checksum a legacy protocol requires
            using var md5 = new MD5Pkcs11(session);
#pragma warning restore KLPKCS11001
            return md5.ComputeHash(data);
        }
        // 3. The using declarations close the session, then the library.
        #endregion
    }

    [SuppressMessage("Security", "S4790:Use a stronger hashing algorithm", Justification = "The software counterpart of the legacy identifier the token example computes (docs/examples/md5.md).")]
    public static byte[] BclMd5(byte[] data)
    {
        #region BclMd5
        // The same identifier in software: no token, so no policy lease.
        byte[] digest = MD5.HashData(data);
        #endregion
        return digest;
    }
}
