using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/sha-2.md: SHA-256, SHA-384 and SHA-512 on the token.</summary>
public static class Sha2Examples
{
    public static byte[][] BclSha2(byte[] data)
    {
        #region BclSha2
        // In software: the static one-shot methods, no instance to dispose.
        byte[][] digests = [SHA256.HashData(data), SHA384.HashData(data), SHA512.HashData(data)];
        #endregion
        return digests;
    }

    public static byte[][] Sha2OnToken(Pkcs11Session session, byte[] data)
    {
        #region Sha2OnToken
        // Each adapter is a HashAlgorithm over the session: ComputeHash, TransformBlock, streams, ...
        using var sha256 = new SHA256Pkcs11(session);
        using var sha384 = new SHA384Pkcs11(session);
        using var sha512 = new SHA512Pkcs11(session);
        byte[][] digests = [sha256.ComputeHash(data), sha384.ComputeHash(data), sha512.ComputeHash(data)];
        #endregion
        return digests;
    }
}
