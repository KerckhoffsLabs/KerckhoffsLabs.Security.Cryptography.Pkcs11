using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Specifies a particular mechanism and any parameters it requires
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_MECHANISM
{
    /// <summary>
    /// The type of mechanism
    /// </summary>
    public NativeCULong Mechanism;

    /// <summary>
    /// Pointer to the parameter if required by the mechanism
    /// </summary>
    public IntPtr Parameter;

    /// <summary>
    /// Length of the parameter in bytes
    /// </summary>
    public NativeCULong ParameterLen;
}
