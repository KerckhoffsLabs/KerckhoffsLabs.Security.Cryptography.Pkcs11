using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure, which provides the parameters to the CKM_WTLS_PRF mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_WTLS_PRF_PARAMS
{
    /// <summary>
    /// Digest mechanism to be used (CKM)
    /// </summary>
    public NativeCULong DigestMechanism;

    /// <summary>
    /// Pointer to the input seed
    /// </summary>
    public IntPtr Seed;

    /// <summary>
    /// Length in bytes of the input seed
    /// </summary>
    public NativeCULong SeedLen;

    /// <summary>
    /// Pointer to the identifying label
    /// </summary>
    public IntPtr Label;

    /// <summary>
    /// Length in bytes of the identifying label
    /// </summary>
    public NativeCULong LabelLen;

    /// <summary>
    /// Pointer receiving the output of the operation
    /// </summary>
    public IntPtr Output;

    /// <summary>
    /// Pointer to the length in bytes that the output to be created shall have, has to hold the desired length as input and will receive the calculated length as output
    /// </summary>
    public IntPtr OutputLen;
}