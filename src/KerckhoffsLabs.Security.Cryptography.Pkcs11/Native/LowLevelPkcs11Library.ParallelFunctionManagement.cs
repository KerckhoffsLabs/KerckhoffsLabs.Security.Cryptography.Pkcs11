// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED</returns>
    public CKR C_GetFunctionStatus(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetFunctionStatus(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED</returns>
    public CKR C_CancelFunction(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_CancelFunction(session);
        return rv.ToCKR();
    }
}
