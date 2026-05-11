using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides and returns parameters for the CKM_DSA_PROBABLISTIC_PARAMETER_GEN, CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN a CKM_DSA_FIPS_G_GEN mechanisms
/// </summary>
[PlatformSpecificPack]
public struct CK_DSA_PARAMETER_GEN_PARAM
{
    /// <summary>
    /// Mechanism value for the base hash used in PQG generation (CKM)
    /// </summary>
    public NativeCULong Hash;

    /// <summary>
    /// Pointer to seed value used to generate PQ and G
    /// </summary>
    public IntPtr Seed;

    /// <summary>
    /// Length of seed value
    /// </summary>
    public NativeCULong SeedLen;

    /// <summary>
    /// Index value for generating G
    /// </summary>
    public NativeCULong Index;
}