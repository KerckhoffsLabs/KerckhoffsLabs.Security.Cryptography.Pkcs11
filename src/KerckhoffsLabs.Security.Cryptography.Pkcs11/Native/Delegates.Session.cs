// <auto-split-from Delegates.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the cryptoki dispatch boundary, and every unsafe region in it is one of " +
    "exactly three things C# permits nowhere else: invoking an unmanaged function pointer, pinning a managed " +
    "buffer for the duration of a native call, and taking the address of a blittable struct to pass as a " +
    "CK_*_PTR. There is no version of this file that satisfies the rule and still dispatches to a PKCS#11 " +
    "module. Suppressed at the type rather than per member so the rule keeps its value everywhere else: an " +
    "unsafe block appearing outside this boundary is still reported, and that is the case worth reviewing. " +
    "The safety argument does not rest on the suppression — every pointer is either pinned by a fixed " +
    "statement scoped to the call, or the address of a local, and every function pointer is null-checked by " +
    "ThrowIfUnbound before invocation. The dispatch table's binding is covered hermetically by " +
    "DelegatesLoaderTests, and the wrappers themselves by the full suite against SoftHSM2 and opencryptoki.")]
internal partial class Delegates
{
    /// <summary>Wrapper for <c>C_InitPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin)
    {
        ThrowIfUnbound(_fp.C_InitPIN);
        fixed (byte* pinPtr = pin)
            return _fp.C_InitPIN(session, pinPtr, (NativeCULong)pin.Length);
    }

    /// <summary>Wrapper for <c>C_SetPIN</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        ThrowIfUnbound(_fp.C_SetPIN);
        fixed (byte* oldPinPtr = oldPin)
        fixed (byte* newPinPtr = newPin)
            return _fp.C_SetPIN(session, oldPinPtr, (NativeCULong)oldPin.Length, newPinPtr, (NativeCULong)newPin.Length);
    }

    /// <summary>Wrapper for <c>C_OpenSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_OpenSession);
        fixed (NativeCULong* sessionPtr = &session)
            return _fp.C_OpenSession(slotId, flags, application, notify, sessionPtr);
    }

    /// <summary>Wrapper for <c>C_CloseSession</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseSession(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_CloseSession);
        return _fp.C_CloseSession(session);
    }

    /// <summary>Wrapper for <c>C_CloseAllSessions</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_CloseAllSessions(NativeCULong slotId)
    {
        ThrowIfUnbound(_fp.C_CloseAllSessions);
        return _fp.C_CloseAllSessions(slotId);
    }

    /// <summary>Wrapper for <c>C_GetSessionInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetSessionInfo_Windows);
            CK_SESSION_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetSessionInfo_Windows(session, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetSessionInfo);
        fixed (CK_SESSION_INFO* p = &info) return _fp.C_GetSessionInfo(session, p);
    }

    /// <summary>Wrapper for <c>C_GetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetOperationState(NativeCULong session, Span<byte> operationState, out NativeCULong operationStateLen)
    {
        operationStateLen = (NativeCULong)operationState.Length;
        ThrowIfUnbound(_fp.C_GetOperationState);
        fixed (byte* statePtr = operationState)
        fixed (NativeCULong* lenPtr = &operationStateLen)
            return _fp.C_GetOperationState(session, statePtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SetOperationState</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey,
        NativeCULong authenticationKey)
    {
        ThrowIfUnbound(_fp.C_SetOperationState);
        fixed (byte* statePtr = operationState)
            return _fp.C_SetOperationState(session, statePtr, (NativeCULong)operationState.Length, encryptionKey, authenticationKey);
    }

    /// <summary>Wrapper for <c>C_Login</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
    {
        ThrowIfUnbound(_fp.C_Login);
        fixed (byte* pinPtr = pin)
            return _fp.C_Login(session, userType, pinPtr, (NativeCULong)pin.Length);
    }

    /// <summary>Wrapper for <c>C_Logout</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Logout(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_Logout);
        return _fp.C_Logout(session);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_LoginUser</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_LoginUser => _fp.C_LoginUser is not null;

    /// <summary>Wrapper for <c>C_LoginUser</c> (PKCS#11 v3.0). Null on v2.40 libraries.</summary>
    public unsafe NativeCULong C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        ThrowIfUnbound(_fp.C_LoginUser);
        fixed (byte* pinPtr = pin)
        fixed (byte* userPtr = username)
            return _fp.C_LoginUser(session, userType, pinPtr, (NativeCULong)pin.Length, userPtr, (NativeCULong)username.Length);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SessionCancel</c> (PKCS#11 v3.0+).</summary>
    public unsafe bool IsC_SessionCancelSupported => _fp.C_SessionCancel is not null;

    /// <summary>Wrapper for <c>C_SessionCancel</c> (PKCS#11 v3.0). Throws <see cref="Pkcs11Exception"/> if the loaded library is v2.40 or does not export the symbol.</summary>
    public unsafe NativeCULong C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        ThrowIfUnbound(_fp.C_SessionCancel);
        return _fp.C_SessionCancel(session, flags);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_GetSessionValidationFlags => _fp.C_GetSessionValidationFlags is not null;

    /// <summary>Wrapper for <c>C_GetSessionValidationFlags</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        ThrowIfUnbound(_fp.C_GetSessionValidationFlags);
        fixed (NativeCULong* flagsPtr = &flags)
            return _fp.C_GetSessionValidationFlags(session, type, flagsPtr);
    }
}
