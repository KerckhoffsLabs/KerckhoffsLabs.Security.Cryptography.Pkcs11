using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_GOSTR3410_KEY_WRAP mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_GOSTR3410_KEY_WRAP_PARAMS
{
    /// <summary>
    /// Pointer to a data with DER-encoding of the object identifier indicating the data object type of GOST 28147-89
    /// </summary>
    public IntPtr WrapOID;

    /// <summary>
    /// Length of data with DER-encoding of the object identifier indicating the data object type of GOST 28147-89
    /// </summary>
    public NativeCULong WrapOIDLen;

    /// <summary>
    /// Pointer to a data with UKM
    /// </summary>
    public IntPtr UKM;

    /// <summary>
    /// Length of UKM data
    /// </summary>
    public NativeCULong UKMLen;

    /// <summary>
    /// Key handle of a sender for wrapping operation or key handle of a receiver for unwrapping operation
    /// </summary>
    public NativeCULong Key;
}