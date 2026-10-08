using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Retrieve the result of a previously-pending async crypto operation (PKCS#11 v3.2 §5.20.2).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result)
    {
        using ModuleCall call = EnterModule();
        var asyncComplete = call.Functions.C_AsyncComplete;
        if (asyncComplete is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // The module reads and writes the block, which starts from the caller's values.
        byte* p = stackalloc byte[Pkcs11Marshal.SizeOf<CK_ASYNC_DATA>()];
        Pkcs11Marshal.WriteStructure((IntPtr)p, in result);
        CKR rv;
        fixed (byte* namePtr = functionName)
            rv = asyncComplete(session, namePtr, p).ToCKR();
        result = Pkcs11Marshal.ReadStructure<CK_ASYNC_DATA>((IntPtr)p);
        return rv;
    }

    /// <summary>
    /// Obtain a persistent identifier for an async operation so it can be rejoined later (PKCS#11 v3.2 §5.20.3).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id)
    {
        using ModuleCall call = EnterModule();
        var asyncGetId = call.Functions.C_AsyncGetID;
        if (asyncGetId is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* namePtr = functionName)
        fixed (NativeCULong* idPtr = &id)
            return asyncGetId(session, namePtr, idPtr).ToCKR();
    }

    /// <summary>
    /// Reattach to a previously-issued async operation using its persistent ID (PKCS#11 v3.2 §5.20.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data)
    {
        using ModuleCall call = EnterModule();
        var asyncJoin = call.Functions.C_AsyncJoin;
        if (asyncJoin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* namePtr = functionName)
        fixed (byte* dataPtr = data)
            return asyncJoin(session, namePtr, id, dataPtr, (NativeCULong)data.Length).ToCKR();
    }
}
