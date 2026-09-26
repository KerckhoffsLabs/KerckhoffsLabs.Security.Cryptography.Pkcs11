namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>A set of <see cref="CryptoOperation"/> values, one bit per member.</summary>
[Flags]
internal enum CryptoOperationSet
{
    None = 0,
    Encrypt = 1 << CryptoOperation.Encrypt,
    Decrypt = 1 << CryptoOperation.Decrypt,
    Sign = 1 << CryptoOperation.Sign,
    Verify = 1 << CryptoOperation.Verify,
    Wrap = 1 << CryptoOperation.Wrap,
    Unwrap = 1 << CryptoOperation.Unwrap,
    Derive = 1 << CryptoOperation.Derive,
    Digest = 1 << CryptoOperation.Digest,
    GenerateKey = 1 << CryptoOperation.GenerateKey,
    GenerateKeyPair = 1 << CryptoOperation.GenerateKeyPair,
    Encapsulate = 1 << CryptoOperation.Encapsulate,
    Decapsulate = 1 << CryptoOperation.Decapsulate,
}

internal static class CryptoOperationSetExtensions
{
    public static bool Contains(this CryptoOperationSet set, CryptoOperation op)
        => (set & (CryptoOperationSet)(1 << (int)op)) != 0;
}
