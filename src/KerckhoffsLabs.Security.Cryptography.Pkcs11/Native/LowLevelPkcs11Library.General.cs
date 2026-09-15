// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Initializes the Cryptoki library
    /// </summary>
    /// <param name="initArgs">CK_C_INITIALIZE_ARGS structure containing information on how the library should deal with multi-threaded access or null if an application will not be accessing Cryptoki through multiple threads simultaneously</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NEED_TO_CREATE_THREADS, CKR_OK</returns>
    public CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (initArgs == null)
        {
            NativeCULong rv = _delegates.C_Initialize(IntPtr.Zero);
            return rv.ToCKR();
        }
        else
        {
            IntPtr pInitArgs = UnmanagedMemory.Allocate(UnmanagedMemory.SizeOf<CK_C_INITIALIZE_ARGS>());
            try
            {
                CK_C_INITIALIZE_ARGS initArgsValue = initArgs.Value;
                UnmanagedMemory.Write(pInitArgs, in initArgsValue);
                NativeCULong rv = _delegates.C_Initialize(pInitArgs);
                return rv.ToCKR();
            }
            finally
            {
                UnmanagedMemory.Free(ref pInitArgs);
            }
        }
    }

    /// <summary>
    /// Called to indicate that an application is finished with the Cryptoki library. It should be the last Cryptoki call made by an application.
    /// </summary>
    /// <param name="reserved">Reserved for future versions. For this version, it should be set to null.</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public CKR C_Finalize(IntPtr reserved)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Finalize(reserved);
        return rv.ToCKR();
    }

    /// <summary>
    /// Returns general information about Cryptoki
    /// </summary>
    /// <param name="info">Structure that receives the information</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public CKR C_GetInfo(ref CK_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetInfo(ref info).ToCKR();
    }

    /// <summary>
    /// Returns a pointer to the Cryptoki library's list of function pointers
    /// </summary>
    /// <param name="functionList">Pointer to a value which will receive a pointer to the library's CK_FUNCTION_LIST structure</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public CKR C_GetFunctionList(out IntPtr functionList)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetFunctionList(out functionList);
        return rv.ToCKR();
    }

    /// <summary>
    /// Lists the interfaces a v3.0+ module exposes (PKCS#11 v3.0 §5.4.4). Standard two-call idiom:
    /// pass <c>null</c> to learn the count, then a buffer of that size to receive the descriptors.
    /// </summary>
    /// <param name="interfaces">Buffer to receive the interface descriptors, or <c>null</c> to query the count.</param>
    /// <param name="count">In/out count: receives the interface count on the null call.</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_GetInterfaceList)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_GetInterfaceList(interfaces, ref count).ToCKR();
    }

    /// <summary>
    /// Obtains a single interface descriptor by name (PKCS#11 v3.0 §5.4.5). The returned struct is
    /// read with the platform-correct layout, so no separate Windows path is needed.
    /// </summary>
    /// <param name="interfaceName">NUL-terminated UTF-8 interface name, or <c>null</c> for the default.</param>
    /// <param name="flags">Interface flags constraining the request (typically 0).</param>
    /// <param name="iface">Receives the token-owned interface descriptor on success.</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_GetInterface)
        {
            iface = default;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        return _delegates.C_GetInterface(interfaceName, flags, out iface).ToCKR();
    }
}
