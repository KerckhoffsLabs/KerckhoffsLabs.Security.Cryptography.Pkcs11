using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED</returns>
    public unsafe CKR C_GetFunctionStatus(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var getFunctionStatus = call.Functions.C_GetFunctionStatus;
        if (getFunctionStatus is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return getFunctionStatus(session).ToCKR();
    }

    /// <summary>
    /// Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED</returns>
    public unsafe CKR C_CancelFunction(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var cancelFunction = call.Functions.C_CancelFunction;
        if (cancelFunction is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return cancelFunction(session).ToCKR();
    }
}
