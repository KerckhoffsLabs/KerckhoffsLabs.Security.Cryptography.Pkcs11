// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Retrieve the result of a previously-pending async crypto operation (PKCS#11 v3.2 §5.20.2).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_AsyncComplete)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return call.Table.C_AsyncComplete(session, functionName, ref result).ToCKR();
    }

    /// <summary>
    /// Obtain a persistent identifier for an async operation so it can be rejoined later (PKCS#11 v3.2 §5.20.3).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_AsyncGetID)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = call.Table.C_AsyncGetID(session, functionName, ref id);
        return rv.ToCKR();
    }

    /// <summary>
    /// Reattach to a previously-issued async operation using its persistent ID (PKCS#11 v3.2 §5.20.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_AsyncJoin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = call.Table.C_AsyncJoin(session, functionName, id, data);
        return rv.ToCKR();
    }
}
