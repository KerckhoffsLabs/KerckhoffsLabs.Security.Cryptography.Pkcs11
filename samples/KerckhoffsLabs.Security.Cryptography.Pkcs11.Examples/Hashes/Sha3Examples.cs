using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/sha-3.md: SHA3-256, SHA3-384 and SHA3-512 on the token.</summary>
public static class Sha3Examples
{
    public static byte[][] Sha3OnToken(Pkcs11Session session, byte[] data)
    {
        #region Sha3OnToken
        using var sha3_256 = new SHA3_256Pkcs11(session);
        using var sha3_384 = new SHA3_384Pkcs11(session);
        using var sha3_512 = new SHA3_512Pkcs11(session);
        byte[][] digests = [sha3_256.ComputeHash(data), sha3_384.ComputeHash(data), sha3_512.ComputeHash(data)];
        #endregion
        return digests;
    }
}
