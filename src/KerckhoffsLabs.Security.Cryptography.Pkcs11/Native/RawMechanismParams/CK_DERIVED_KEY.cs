using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Describes an additional key to be derived in a single SP800-108 KDF call (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_DERIVED_KEY
{
    /// <summary>
    /// Pointer to an array of CK_ATTRIBUTE describing the derived key.
    /// </summary>
    public IntPtr Template;

    /// <summary>
    /// Number of entries in Template.
    /// </summary>
    public NativeCULong AttributeCount;

    /// <summary>
    /// Pointer to a CK_OBJECT_HANDLE that receives the derived key handle.
    /// </summary>
    public IntPtr Key;
}
