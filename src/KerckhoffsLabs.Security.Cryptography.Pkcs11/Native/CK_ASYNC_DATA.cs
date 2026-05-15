using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Async-API result descriptor used with C_AsyncComplete (PKCS#11 v3.2 §5.20). The
/// library fills this struct on completion of a previously-pending crypto operation
/// kicked off on a CKF_ASYNC_SESSION-flagged session.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_ASYNC_DATA
{
    /// <summary>Struct version for forward compatibility.</summary>
    public NativeCULong Version;

    /// <summary>Pointer to result bytes (e.g. ciphertext for an async encrypt).</summary>
    public IntPtr Value;

    /// <summary>Length of the result in bytes.</summary>
    public NativeCULong ValueLen;

    /// <summary>Primary object handle produced by the operation (e.g. derived key handle).</summary>
    public NativeCULong Object;

    /// <summary>Secondary object handle (e.g. additional output key from key-pair gen).</summary>
    public NativeCULong AdditionalObject;
}
