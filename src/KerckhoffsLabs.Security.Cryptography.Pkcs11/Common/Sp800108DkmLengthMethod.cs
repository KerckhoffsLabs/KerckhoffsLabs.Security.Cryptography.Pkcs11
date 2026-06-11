namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// How the derived-keying-material length [L] is computed for an SP800-108 KDF
/// <c>DKM_LENGTH</c> data segment (PKCS#11 v3.0 <c>CK_SP800_108_DKM_LENGTH_METHOD</c>).
/// </summary>
public enum Sp800108DkmLengthMethod : uint
{
    /// <summary>[L] is the sum of the lengths of all keys derived in the call (CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS).</summary>
    SumOfKeys = 0x00000001,

    /// <summary>[L] is the sum of the lengths of all PRF output segments produced (CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS).</summary>
    SumOfSegments = 0x00000002,
}
