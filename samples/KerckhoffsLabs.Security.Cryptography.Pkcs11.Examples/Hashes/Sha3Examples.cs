using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/sha-3.md: SHA3-256, SHA3-384 and SHA3-512 on the token.</summary>
public static class Sha3Examples
{
    public static byte[][] Sha3OnToken(string modulePath, string tokenLabel, byte[] data)
    {
        #region Sha3OnToken
        // 1. Load the module (its path from configuration) and open a session on the token. Hashing
        //    uses no key, so no login: a public session will do. Where a token wants a login for every
        //    operation, open it with OpenSessionWithPin, as on the key pages.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithoutLogin(tokenLabel);

        // 2. Hash on the token, as with SHA-2.
        using var sha3_256 = new SHA3_256Pkcs11(session);
        using var sha3_384 = new SHA3_384Pkcs11(session);
        using var sha3_512 = new SHA3_512Pkcs11(session);
        byte[][] digests = [sha3_256.ComputeHash(data), sha3_384.ComputeHash(data), sha3_512.ComputeHash(data)];
        // 3. The using declarations dispose the adapters, then close the session and the library.
        #endregion
        return digests;
    }

    public static byte[][]? BclSha3(byte[] data)
    {
        #region BclSha3
        // In software, SHA-3 needs platform support (OpenSSL 1.1.1 or later, or a recent Windows): check first.
        byte[][]? digests = SHA3_256.IsSupported
            ? [SHA3_256.HashData(data), SHA3_384.HashData(data), SHA3_512.HashData(data)]
            : null;
        #endregion
        return digests;
    }
}
