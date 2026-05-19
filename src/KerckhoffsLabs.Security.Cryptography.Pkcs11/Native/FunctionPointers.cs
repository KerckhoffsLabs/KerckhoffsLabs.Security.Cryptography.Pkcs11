using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds the raw <c>delegate* unmanaged[Cdecl]&lt;...&gt;</c> function pointers for every
/// PKCS#11 cryptoki function the library binds. Populated by direct cast from
/// <see cref="CK_FUNCTION_LIST"/> / <see cref="CK_FUNCTION_LIST_3_0"/> / <see cref="CK_FUNCTION_LIST_3_2"/>
/// entries; no <c>Marshal.GetDelegateForFunctionPointer&lt;T&gt;</c> on this path so the
/// dispatch table is fully Native AOT compatible.
/// </summary>
/// <remarks>
/// Wrapper methods on <see cref="Delegates"/> do the per-call marshalling (pinning
/// <c>byte[]</c> / <c>CK_*[]</c> / <c>NativeCULong[]</c>, taking <c>fixed</c> addresses of
/// ref-struct parameters, converting <c>bool</c>↔<c>byte</c>) so the public dispatch
/// surface stays identical to the prior delegate-based version.
/// </remarks>
internal sealed unsafe class FunctionPointers
{
    /// <summary>Cryptoki <c>CK_RV C_Finalize(CK_VOID_PTR pReserved)</c>.</summary>
    public delegate* unmanaged[Cdecl]<IntPtr, NativeCULong> C_Finalize;

    /// <summary>Cryptoki <c>CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseSession;

    /// <summary>Cryptoki <c>CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CloseAllSessions;

    /// <summary>Cryptoki <c>CK_RV C_Logout(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_Logout;

    /// <summary>Cryptoki <c>CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_DestroyObject;

    /// <summary>Cryptoki <c>CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_FindObjectsFinal;

    /// <summary>Cryptoki <c>CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)</c> (v3.0+).</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, NativeCULong> C_SessionCancel;

    /// <summary>Cryptoki <c>CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong> C_CancelFunction;

    /// <summary>Cryptoki <c>CK_RV C_GetInfo(CK_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<CK_INFO*, NativeCULong> C_GetInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SLOT_INFO*, NativeCULong> C_GetSlotInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_TOKEN_INFO*, NativeCULong> C_GetTokenInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, CK_SESSION_INFO*, NativeCULong> C_GetSessionInfo;

    /// <summary>Cryptoki <c>CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)</c>.</summary>
    public delegate* unmanaged[Cdecl]<NativeCULong, NativeCULong, CK_MECHANISM_INFO*, NativeCULong> C_GetMechanismInfo;

    // Additional fields are added one group at a time in subsequent tasks.
}
