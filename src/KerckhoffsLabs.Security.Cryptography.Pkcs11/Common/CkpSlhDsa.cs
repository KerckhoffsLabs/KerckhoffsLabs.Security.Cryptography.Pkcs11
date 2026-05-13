namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// SLH-DSA parameter-set identifier (FIPS 205 / PKCS#11 v3.2). 12 standardized
/// parameter sets across three security levels and two performance trade-offs
/// (the 'S' suffix = small signature, slower; 'F' suffix = fast signing, larger signature).
/// </summary>
public enum CkpSlhDsa : uint
{
    /// <summary>SLH-DSA-SHA2-128s: SHA2 family, NIST level 1, small signature (~7.8 KB).</summary>
    CKP_SLH_DSA_SHA2_128S = 0x00000001,
    /// <summary>SLH-DSA-SHAKE-128s: SHAKE family, NIST level 1, small signature.</summary>
    CKP_SLH_DSA_SHAKE_128S = 0x00000002,
    /// <summary>SLH-DSA-SHA2-128f: SHA2 family, NIST level 1, fast signing (~17 KB signature).</summary>
    CKP_SLH_DSA_SHA2_128F = 0x00000003,
    /// <summary>SLH-DSA-SHAKE-128f: SHAKE family, NIST level 1, fast signing.</summary>
    CKP_SLH_DSA_SHAKE_128F = 0x00000004,
    /// <summary>SLH-DSA-SHA2-192s: SHA2 family, NIST level 3, small signature.</summary>
    CKP_SLH_DSA_SHA2_192S = 0x00000005,
    /// <summary>SLH-DSA-SHAKE-192s: SHAKE family, NIST level 3, small signature.</summary>
    CKP_SLH_DSA_SHAKE_192S = 0x00000006,
    /// <summary>SLH-DSA-SHA2-192f: SHA2 family, NIST level 3, fast signing.</summary>
    CKP_SLH_DSA_SHA2_192F = 0x00000007,
    /// <summary>SLH-DSA-SHAKE-192f: SHAKE family, NIST level 3, fast signing.</summary>
    CKP_SLH_DSA_SHAKE_192F = 0x00000008,
    /// <summary>SLH-DSA-SHA2-256s: SHA2 family, NIST level 5, small signature.</summary>
    CKP_SLH_DSA_SHA2_256S = 0x00000009,
    /// <summary>SLH-DSA-SHAKE-256s: SHAKE family, NIST level 5, small signature.</summary>
    CKP_SLH_DSA_SHAKE_256S = 0x0000000A,
    /// <summary>SLH-DSA-SHA2-256f: SHA2 family, NIST level 5, fast signing.</summary>
    CKP_SLH_DSA_SHA2_256F = 0x0000000B,
    /// <summary>SLH-DSA-SHAKE-256f: SHAKE family, NIST level 5, fast signing.</summary>
    CKP_SLH_DSA_SHAKE_256F = 0x0000000C,
}
