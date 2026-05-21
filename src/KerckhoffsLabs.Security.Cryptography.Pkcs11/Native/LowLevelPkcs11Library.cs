using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed class LowLevelPkcs11Library : ILowLevelPkcs11Library
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Handle to the PKCS#11 library
    /// </summary>
    private Pkcs11ModuleHandle _library = new Pkcs11ModuleHandle();

    /// <summary>
    /// Delegates for PKCS#11 functions
    /// </summary>
    private readonly Delegates _delegates;

    /// <summary>
    /// Lock guarding <see cref="_trackedSessions"/>.
    /// </summary>
    private readonly Lock _sessionsLock = new();

    /// <summary>
    /// Weak references to every <see cref="Pkcs11SessionHandle"/> opened against this library.
    /// Cleared by <see cref="CloseAllTrackedSessions"/> at <see cref="Pkcs11Library.Dispose()"/>
    /// time so we can issue a graceful <c>C_CloseSession</c> while the function table is still
    /// valid — without preventing GC of normally-disposed sessions.
    /// </summary>
    private readonly List<WeakReference<Pkcs11SessionHandle>> _trackedSessions = [];

    /// <summary>
    /// Test seam: current count of tracked (still-live) session handles. Prunes dead
    /// weak refs on read so the count reflects what's actually reachable.
    /// </summary>
    public int TrackedSessionCount
    {
        get
        {
            lock (_sessionsLock)
            {
                _trackedSessions.RemoveAll(wr => !wr.TryGetTarget(out _));
                return _trackedSessions.Count;
            }
        }
    }

    /// <summary>
    /// Registers a session handle for cleanup at library teardown. Called from the
    /// <see cref="Pkcs11SessionHandle"/> constructor.
    /// </summary>
    public void RegisterSession(Pkcs11SessionHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        lock (_sessionsLock)
        {
            _trackedSessions.RemoveAll(wr => !wr.TryGetTarget(out _));
            _trackedSessions.Add(new WeakReference<Pkcs11SessionHandle>(handle));
        }
    }

    /// <summary>
    /// Removes <paramref name="handle"/> from the tracker. Called from
    /// <see cref="Pkcs11SessionHandle.ReleaseHandle"/> after a normal close so the
    /// tracker doesn't grow unbounded.
    /// </summary>
    public void UnregisterSession(Pkcs11SessionHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        lock (_sessionsLock)
        {
            _trackedSessions.RemoveAll(wr =>
                !wr.TryGetTarget(out var h) || ReferenceEquals(h, handle));
        }
    }

    /// <summary>
    /// Closes every still-live tracked session handle. Must run before <c>C_Finalize</c>
    /// and before the module is unloaded — otherwise a stray <see cref="Pkcs11SessionHandle"/>
    /// finalizer would call <c>C_CloseSession</c> through a function table whose backing
    /// module has been unmapped. <see cref="SafeHandle.Dispose()"/> is reentrant and
    /// thread-safe, so it's safe to invoke even if the user races us by disposing the same
    /// session on another thread.
    /// </summary>
    public void CloseAllTrackedSessions()
    {
        Pkcs11SessionHandle[] live;
        lock (_sessionsLock)
        {
            live = [.. _trackedSessions
                .Select(wr => wr.TryGetTarget(out var h) ? h : null)
                .Where(h => h is not null)
                .Cast<Pkcs11SessionHandle>()];
            _trackedSessions.Clear();
        }

        foreach (var handle in live)
        {
            try
            {
                if (handle.IsClosed || handle.IsInvalid) continue;
                handle.Dispose();
            }
            catch
            {
                // Best-effort cleanup; never let one bad handle block another's close.
            }
        }
    }

    /// <summary>
    /// Loads PKCS#11 library at <paramref name="libraryPath"/> and acquires function
    /// pointers via <c>C_GetFunctionList</c>.
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    public LowLevelPkcs11Library(string libraryPath)
    {
        EnsureCkUlongWidthMatchesPlatform();
        ArgumentException.ThrowIfNullOrEmpty(libraryPath);
        try
        {
            _library = new Pkcs11ModuleHandle(NativeLibrary.Load(libraryPath));
            _delegates = new Delegates(_library.DangerousGetHandle());
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Binds to a statically-linked PKCS#11 implementation. The cryptoki symbols
    /// are expected to be linked into the host executable (iOS-style
    /// <c>DllImport("__Internal")</c>). The function-list pointer is acquired via
    /// the statically-bound <c>C_GetFunctionList</c>; all subsequent calls go
    /// through the returned function-pointer table, same as the dynamic-load path.
    /// </summary>
    internal LowLevelPkcs11Library()
    {
        EnsureCkUlongWidthMatchesPlatform();
        try
        {
            _delegates = new Delegates(IntPtr.Zero);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Verifies the resolved build's CK_ULONG width (<see cref="NativeCULong"/>) matches the
    /// host's native CK_ULONG: 4 bytes on Windows (LLP64), the pointer width on Unix (LP64/ILP32).
    /// <see cref="NativeCULong"/> is <c>uint</c> in the net10.0-windows build and <c>nuint</c> in
    /// the neutral net10.0 build, so a net10.0 build on Windows x64 (8 bytes) or a net10.0-windows
    /// build on Unix-64 (4 bytes) would silently mis-marshal every CK_ULONG-bearing struct. Fail
    /// loudly instead — the caller resolved the wrong target-framework asset.
    /// </summary>
    private static void EnsureCkUlongWidthMatchesPlatform()
    {
        int expected = OperatingSystem.IsWindows() ? sizeof(uint) : IntPtr.Size;
        int actual = Marshal.SizeOf<NativeCULong>();
        if (actual != expected)
        {
            throw new PlatformNotSupportedException(
                $"CK_ULONG width mismatch: this build's NativeCULong is {actual} bytes but the " +
                $"native CK_ULONG on this platform is {expected} bytes. On Windows, reference " +
                "KerckhoffsLabs.Security.Cryptography.Pkcs11 from a net10.0-windows target framework " +
                "so the 4-byte build is resolved; on Unix use the neutral net10.0 build.");
        }
    }

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

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetInfo_Windows)
        {
            var winInfo = default(CK_INFO_Windows);
            var rv = _delegates.C_GetInfo_Windows(ref winInfo);
            info = winInfo.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetInfo(ref info);
        return rv2.ToCKR();
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
    /// Obtains a list of slots in the system
    /// </summary>
    /// <param name="tokenPresent">Indicates whether the list obtained includes only those slots with a token present (true) or all slots (false)</param>
    /// <param name="slotList">
    /// If set to null then the number of slots is returned in "count" parameter, without actually returning a list of slots.
    /// If not set to null then "count" parameter must contain the lenght of slotList array and slot list is returned in "slotList" parameter.
    /// </param>
    /// <param name="count">Location that receives the number of slots</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetSlotList(tokenPresent, slotList, ref count);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular slot in the system
    /// </summary>
    /// <param name="slotId">The ID of the slot</param>
    /// <param name="info">Structure that receives the slot information</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID</returns>
    public CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetSlotInfo_Windows)
        {
            var winInfo = default(CK_SLOT_INFO_Windows);
            var rv = _delegates.C_GetSlotInfo_Windows(slotId, ref winInfo);
            info = winInfo.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetSlotInfo(slotId, ref info);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular token in the system
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="info">Structure that receives the token information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetTokenInfo_Windows)
        {
            var winInfo = default(CK_TOKEN_INFO_Windows);
            var rv = _delegates.C_GetTokenInfo_Windows(slotId, ref winInfo);
            info = winInfo.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetTokenInfo(slotId, ref info);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Obtains a list of mechanism types supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="mechanismList">
    /// If set to null then the number of mechanisms is returned in "count" parameter, without actually returning a list of mechanisms.
    /// If not set to null then "count" parameter must contain the lenght of mechanismList array and mechanism list is returned in "mechanismList" parameter.
    /// </param>
    /// <param name="count">Location that receives the number of mechanisms</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong[]? CULongList = mechanismList != null
            ? new NativeCULong[mechanismList.Length]
            : null;

        NativeCULong rv = _delegates.C_GetMechanismList(slotId, CULongList, ref count);

        if (mechanismList != null && CULongList != null)
        {
            for (int i = 0; i < mechanismList.Length; i++)
                // Deliberately an unvalidated cast, not ToCKM(): a token may report vendor-defined
                // mechanisms (>= CKM_VENDOR_DEFINED) that are not declared CKM members, and the
                // validating conversion would throw mid-enumeration.
                mechanismList[i] = (CKM)(ulong)CULongList[i];
        }

        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular mechanism possibly supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="type">The type of mechanism</param>
    /// <param name="info">Structure that receives the mechanism information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetMechanismInfo_Windows)
        {
            var winInfo = default(CK_MECHANISM_INFO_Windows);
            var rv = _delegates.C_GetMechanismInfo_Windows(slotId, type.ToCULong(), ref winInfo);
            info = winInfo.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetMechanismInfo(slotId, type.ToCULong(), ref info);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Initializes a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="pin">SO's initial PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="pinLen">The length of the PIN in bytes</param>
    /// <param name="label">32-byte long label of the token which must be padded with blank characters</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_InitToken(NativeCULong slotId, byte[] pin, NativeCULong pinLen, byte[] label)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_InitToken(slotId, pin, pinLen, label);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="pin">Normal user's PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="pinLen">The length of the PIN in bytes</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_SESSION_CLOSED, CKR_SESSION_READ_ONLY, CKR_SESSION_HANDLE_INVALID, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN, CKR_ARGUMENTS_BAD</returns>
    public CKR C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_InitPIN(session, pin, pinLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="oldPin">Old PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="oldPinLen">The length of the old PIN in bytes</param>
    /// <param name="newPin">New PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="newPinLen">The length of the new PIN in bytes</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SetPIN(session, oldPin, oldPinLen, newPin, newPinLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="flags">Flags indicating the type of session</param>
    /// <param name="application">An application defined pointer to be passed to the notification callback</param>
    /// <param name="notify">The address of the notification callback function</param>
    /// <param name="session">Location that receives the handle for the new session</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_OpenSession(slotId, flags, application, notify, ref session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_CloseSession(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_CloseSession(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Closes all sessions an application has with a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT</returns>
    public CKR C_CloseAllSessions(NativeCULong slotId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_CloseAllSessions(slotId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="info">Structure that receives the session information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetSessionInfo_Windows)
        {
            var winInfo = default(CK_SESSION_INFO_Windows);
            var rv = _delegates.C_GetSessionInfo_Windows(session, ref winInfo);
            info = winInfo.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetSessionInfo(session, ref info);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as byte array
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">
    /// If set to null then the length of state is returned in "operationStateLen" parameter, without actually returning a state.
    /// If not set to null then "operationStateLen" parameter must contain the lenght of operationState array and state is returned in "operationState" parameter.
    /// </param>
    /// <param name="operationStateLen">Location that receives the length in bytes of the state</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_STATE_UNSAVEABLE, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetOperationState(NativeCULong session, byte[]? operationState, ref NativeCULong operationStateLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetOperationState(session, operationState, ref operationStateLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from bytes obtained with C_GetOperationState
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="operationState">Saved session state</param>
    /// <param name="operationStateLen">Length of saved session state</param>
    /// <param name="encryptionKey">Handle to the key which will be used for an ongoing encryption or decryption operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <param name="authenticationKey">Handle to the key which will be used for an ongoing operation in the restored session or CK_INVALID_HANDLE if not needed</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_CHANGED, CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_OK, CKR_SAVED_STATE_INVALID, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD</returns>
    public CKR C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SetOperationState(session, operationState, operationStateLen, encryptionKey, authenticationKey);
        return rv.ToCKR();
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="userType">The user type</param>
    /// <param name="pin">User's PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="pinLen">Length of user's PIN</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID</returns>
    public CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Login(session, userType.ToCULong(), pin, pinLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD
    /// functions (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal +
    /// matching Decrypt variants). False on v2.40 libraries.
    /// </summary>
    public bool IsMessageApiSupported
        => _delegates is not null
           && _delegates.HasC_MessageEncryptInit
           && _delegates.HasC_EncryptMessage
           && _delegates.HasC_MessageEncryptFinal
           && _delegates.HasC_MessageDecryptInit
           && _delegates.HasC_DecryptMessage
           && _delegates.HasC_MessageDecryptFinal;

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.2 surface (ML-KEM
    /// encapsulate/decapsulate, authenticated wrap/unwrap, signature-only verify, and
    /// validation-flags inspection). False on v2.40 / v3.0 / v3.1 libraries.
    /// </summary>
    public bool IsV32ApiSupported
        => _delegates is not null
           && _delegates.HasC_EncapsulateKey
           && _delegates.HasC_DecapsulateKey
           && _delegates.HasC_WrapKeyAuthenticated
           && _delegates.HasC_UnwrapKeyAuthenticated
           && _delegates.HasC_VerifySignatureInit
           && _delegates.HasC_VerifySignature
           && _delegates.HasC_GetSessionValidationFlags;

    /// <summary>
    /// Logs a user into a token by user type plus a free-form username (PKCS#11 v3.0 §5.6.7).
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="userType">The user type.</param>
    /// <param name="pin">User's PIN bytes, or null for protected-authentication-path tokens.</param>
    /// <param name="pinLen">Length of <paramref name="pin"/> in bytes.</param>
    /// <param name="username">Username bytes (UTF-8), or null.</param>
    /// <param name="usernameLen">Length of <paramref name="username"/> in bytes.</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_LoginUser(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_LoginUser)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_LoginUser(session, userType.ToCULong(), pin, pinLen, username, usernameLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Cancels operations in-flight on the session matching the given flags bitmask
    /// (PKCS#11 v3.0 §5.6.8). The session remains open; only the targeted operations
    /// are unwound.
    /// </summary>
    /// <param name="session">The session's handle.</param>
    /// <param name="flags">Bitmask of operations to cancel (CKF_ENCRYPT, CKF_DECRYPT, CKF_SIGN, etc.).</param>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.IsC_SessionCancelSupported)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SessionCancel(session, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins an AEAD encrypt-message sequence (PKCS#11 v3.0 §5.9.4). Pair with C_EncryptMessage or C_EncryptMessageBegin/Next + C_MessageEncryptFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageEncryptInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_MessageEncryptInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_MessageEncryptInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_MessageEncryptInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// One-shot AEAD encrypt of a message (PKCS#11 v3.0 §5.9.5). parameter holds the per-message nonce/IV.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessage)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_EncryptMessage(session, parameter, parameterLen, associatedData, associatedDataLen, plaintext, plaintextLen, ciphertext, ref ciphertextLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.6); follow with C_EncryptMessageNext calls.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_EncryptMessageBegin(session, parameter, parameterLen, associatedData, associatedDataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Encrypts a plaintext chunk in a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] plaintextPart, NativeCULong plaintextPartLen, byte[] ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessageNext)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_EncryptMessageNext(session, parameter, parameterLen, plaintextPart, plaintextPartLen, ciphertextPart, ref ciphertextPartLen, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends an AEAD encrypt-message sequence on the session (PKCS#11 v3.0 §5.9.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageEncryptFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageEncryptFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageEncryptFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins an AEAD decrypt-message sequence (PKCS#11 v3.0 §5.10.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageDecryptInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_MessageDecryptInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_MessageDecryptInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_MessageDecryptInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// One-shot AEAD decrypt of a message (PKCS#11 v3.0 §5.10.5). Returns CKR_AEAD_DECRYPT_FAILED on tag-verification failure.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_DecryptMessage)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_DecryptMessage(session, parameter, parameterLen, associatedData, associatedDataLen, ciphertext, ciphertextLen, plaintext, ref plaintextLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_DecryptMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_DecryptMessageBegin(session, parameter, parameterLen, associatedData, associatedDataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Decrypts a ciphertext chunk in a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] ciphertextPart, NativeCULong ciphertextPartLen, byte[] plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_DecryptMessageNext)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_DecryptMessageNext(session, parameter, parameterLen, ciphertextPart, ciphertextPartLen, plaintextPart, ref plaintextPartLen, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends an AEAD decrypt-message sequence on the session (PKCS#11 v3.0 §5.10.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageDecryptFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageDecryptFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageDecryptFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a message-signing sequence (PKCS#11 v3.0 §5.13.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageSignInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_MessageSignInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_MessageSignInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_MessageSignInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// One-shot message sign (PKCS#11 v3.0 §5.13.7).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessage)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SignMessage(session, parameter, parameterLen, data, dataLen, signature, ref signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming message sign (PKCS#11 v3.0 §5.13.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SignMessageBegin(session, parameter, parameterLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Signs a data chunk in a streaming message sign (PKCS#11 v3.0 §5.13.9). signature is only written on the last call when end-of-message is signaled.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessageNext)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SignMessageNext(session, parameter, parameterLen, data, dataLen, signature, ref signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends a message-signing sequence on the session (PKCS#11 v3.0 §5.13.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageSignFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageSignFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageSignFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a message-verification sequence (PKCS#11 v3.0 §5.15.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageVerifyInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_MessageVerifyInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_MessageVerifyInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_MessageVerifyInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// One-shot message verify (PKCS#11 v3.0 §5.15.7). Returns CKR_SIGNATURE_INVALID on a bad signature.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessage)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessage(session, parameter, parameterLen, data, dataLen, signature, signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming message verify (PKCS#11 v3.0 §5.15.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessageBegin(session, parameter, parameterLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Verifies a data chunk in a streaming verify (PKCS#11 v3.0 §5.15.9).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessageNext)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessageNext(session, parameter, parameterLen, data, dataLen, signature, signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends a message-verification sequence on the session (PKCS#11 v3.0 §5.15.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageVerifyFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageVerifyFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageVerifyFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// ML-KEM-style key encapsulation (PKCS#11 v3.2 §5.18.10). Takes an encapsulating public key, returns ciphertext + a handle to the encapsulated shared-secret key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncapsulateKey)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_EncapsulateKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_EncapsulateKey_Windows(session, ref winMech, publicKey, winTpl, attributeCount, ciphertext, ref ciphertextLen, ref derivedKey);
        }
        NativeCULong rv = _delegates.C_EncapsulateKey(session, ref mechanism, publicKey, template, attributeCount, ciphertext, ref ciphertextLen, ref derivedKey);
        return rv.ToCKR();
    }

    /// <summary>
    /// ML-KEM-style key decapsulation (PKCS#11 v3.2 §5.18.11). Reverses C_EncapsulateKey using the matching private key.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_DecapsulateKey)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_DecapsulateKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_DecapsulateKey_Windows(session, ref winMech, privateKey, winTpl, attributeCount, ciphertext, ciphertextLen, ref derivedKey);
        }
        NativeCULong rv = _delegates.C_DecapsulateKey(session, ref mechanism, privateKey, template, attributeCount, ciphertext, ciphertextLen, ref derivedKey);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initialize a signature-only verify operation, supplying the signature up front (PKCS#11 v3.2 §5.16.10). Data is fed via C_VerifySignature(Update) and the final check happens in C_VerifySignatureFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_VerifySignatureInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_VerifySignatureInit_Windows(session, ref winMech, key, signature, signatureLen);
        }
        NativeCULong rv = _delegates.C_VerifySignatureInit(session, ref mechanism, key, signature, signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// One-shot verify against the signature bound at init time (PKCS#11 v3.2 §5.16.11).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignature)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignature(session, data, dataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Feed a data chunk to a streaming signature-only verify (PKCS#11 v3.2 §5.16.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureUpdate)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignatureUpdate(session, part, partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Conclude a streaming signature-only verify; returns CKR_OK on match, CKR_SIGNATURE_INVALID otherwise (PKCS#11 v3.2 §5.16.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifySignatureFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifySignatureFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifySignatureFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type (PKCS#11 v3.2 §5.6.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_GetSessionValidationFlags)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_GetSessionValidationFlags(session, type, ref flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Retrieve the result of a previously-pending async crypto operation (PKCS#11 v3.2 §5.20.2).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncComplete(NativeCULong session, byte[] functionName, ref CK_ASYNC_DATA result)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_AsyncComplete)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_AsyncComplete_Windows)
        {
            var winResult = default(CK_ASYNC_DATA_Windows);
            var rv = _delegates.C_AsyncComplete_Windows(session, functionName, ref winResult);
            result = winResult.ToUnified();
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_AsyncComplete(session, functionName, ref result);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Obtain a persistent identifier for an async operation so it can be rejoined later (PKCS#11 v3.2 §5.20.3).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncGetID(NativeCULong session, byte[] functionName, ref NativeCULong id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_AsyncGetID)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_AsyncGetID(session, functionName, ref id);
        return rv.ToCKR();
    }

    /// <summary>
    /// Reattach to a previously-issued async operation using its persistent ID (PKCS#11 v3.2 §5.20.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_AsyncJoin(NativeCULong session, byte[] functionName, NativeCULong id, byte[] data, NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_AsyncJoin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_AsyncJoin(session, functionName, id, data, dataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Wraps a key with authentication: the wrap is bound to the AAD bytes which must be supplied at unwrap (PKCS#11 v3.2 §5.18.12).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_WrapKeyAuthenticated)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_WrapKeyAuthenticated_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_WrapKeyAuthenticated_Windows(session, ref winMech, wrappingKey, key, associatedData, associatedDataLen, wrappedKey, ref wrappedKeyLen);
        }
        NativeCULong rv = _delegates.C_WrapKeyAuthenticated(session, ref mechanism, wrappingKey, key, associatedData, associatedDataLen, wrappedKey, ref wrappedKeyLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Unwrap counterpart to C_WrapKeyAuthenticated; verifies the AAD as part of the unwrap (PKCS#11 v3.2 §5.18.13).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_UnwrapKeyAuthenticated)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_UnwrapKeyAuthenticated_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_UnwrapKeyAuthenticated_Windows(session, ref winMech, unwrappingKey, wrappedKey, wrappedKeyLen, winTpl, attributeCount, associatedData, associatedDataLen, ref key);
        }
        NativeCULong rv = _delegates.C_UnwrapKeyAuthenticated(session, ref mechanism, unwrappingKey, wrappedKey, wrappedKeyLen, template, attributeCount, associatedData, associatedDataLen, ref key);
        return rv.ToCKR();
    }



    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_Logout(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Logout(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Creates a new object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="template">Object's template</param>
    /// <param name="count">The number of attributes in the template</param>
    /// <param name="objectId">Location that receives the new object's handle</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong objectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_CreateObject_Windows)
        {
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_CreateObject_Windows(session, winTpl, count, ref objectId);
        }
        NativeCULong rv = _delegates.C_CreateObject(session, template, count, ref objectId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template for the new object</param>
    /// <param name="count">The number of attributes in the template</param>
    /// <param name="newObjectId">Location that receives the handle for the copy of the object</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong newObjectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_CopyObject_Windows)
        {
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_CopyObject_Windows(session, objectId, winTpl, count, ref newObjectId);
        }
        NativeCULong rv = _delegates.C_CopyObject(session, objectId, template, count, ref newObjectId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED</returns>
    public CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DestroyObject(session, objectId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Gets the size of an object in bytes
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="size">Location that receives the size in bytes of the object</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetObjectSize(session, objectId, ref size);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be obtained, and receives the attribute values</param>
    /// <param name="count">The number of attributes in the template</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GetAttributeValue_Windows)
        {
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            var rv = _delegates.C_GetAttributeValue_Windows(session, objectId, winTpl, count);
            if (winTpl is not null && template is not null)
            {
                for (int i = 0; i < winTpl.Length; i++)
                    template[i] = winTpl[i].ToUnified();
            }
            return (CKR)(ulong)rv;
        }
        NativeCULong rv2 = _delegates.C_GetAttributeValue(session, objectId, template, count);
        return rv2.ToCKR();
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be modified and their new values</param>
    /// <param name="count">The number of attributes in the template</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_SetAttributeValue_Windows)
        {
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_SetAttributeValue_Windows(session, objectId, winTpl, count);
        }
        NativeCULong rv = _delegates.C_SetAttributeValue(session, objectId, template, count);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a template
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="template">Search template that specifies the attribute values to match</param>
    /// <param name="count">The number of attributes in the search template</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_FindObjectsInit_Windows)
        {
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_FindObjectsInit_Windows(session, winTpl, count);
        }
        NativeCULong rv = _delegates.C_FindObjectsInit(session, template, count);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">Location that receives the list (array) of additional object handles</param>
    /// <param name="maxObjectCount">The maximum number of object handles to be returned</param>
    /// <param name="objectCount">Location that receives the actual number of object handles returned</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_FindObjects(session, objectId, maxObjectCount, ref objectCount);
        return rv.ToCKR();
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjectsFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_FindObjectsFinal(session);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes an encryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The encryption mechanism</param>
    /// <param name="key">The handle of the encryption key</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_EncryptInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_EncryptInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_EncryptInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be encrypted</param>
    /// <param name="dataLen">Length of data in bytes</param>
    /// <param name="encryptedData">
    /// If set to null then the length of encrypted data is returned in "encryptedDataLen" parameter, without actually returning encrypted data.
    /// If not set to null then "encryptedDataLen" parameter must contain the lenght of encryptedData array and encrypted data is returned in "encryptedData" parameter.
    /// </param>
    /// <param name="encryptedDataLen">Location that holds the length in bytes of the encrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encryptedData, ref NativeCULong encryptedDataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Encrypt(session, data, dataLen, encryptedData, ref encryptedDataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be encrypted</param>
    /// <param name="partLen">Length of data part in bytes</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_EncryptUpdate(session, part, partLen, encryptedPart, ref encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part encryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastEncryptedPart">
    /// If set to null then the length of last encrypted data part is returned in "lastEncryptedPartLen" parameter, without actually returning last encrypted data part.
    /// If not set to null then "lastEncryptedPartLen" parameter must contain the lenght of lastEncryptedPart array and last encrypted data part is returned in "lastEncryptedPart" parameter.
    /// </param>
    /// <param name="lastEncryptedPartLen">Location that holds the length of the last encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_EncryptFinal(NativeCULong session, byte[]? lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_EncryptFinal(session, lastEncryptedPart, ref lastEncryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a decryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The decryption mechanism</param>
    /// <param name="key">The handle of the decryption key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_DecryptInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_DecryptInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_DecryptInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Decrypts encrypted data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedData">Encrypted data</param>
    /// <param name="encryptedDataLen">The length of the encrypted data</param>
    /// <param name="data">
    /// If set to null then the length of decrypted data is returned in "dataLen" parameter, without actually returning decrypted data.
    /// If not set to null then "dataLen" parameter must contain the lenght of data array and decrypted data is returned in "data" parameter.
    /// </param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[]? data, ref NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Decrypt(session, encryptedData, encryptedDataLen, data, ref dataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part decryption operation, processing another encrypted data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="encryptedPartLen">Length of the encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptUpdate(session, encryptedPart, encryptedPartLen, part, ref partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part decryption operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="lastPart">
    /// If set to null then the length of last decrypted data part is returned in "lastPartLen" parameter, without actually returning last decrypted data part.
    /// If not set to null then "lastPartLen" parameter must contain the lenght of lastPart array and last decrypted data part is returned in "lastPart" parameter.
    /// </param>
    /// <param name="lastPartLen">Location that holds the length of the last decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DecryptFinal(NativeCULong session, byte[]? lastPart, ref NativeCULong lastPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptFinal(session, lastPart, ref lastPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a message-digesting operation
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The digesting mechanism</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_DigestInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_DigestInit_Windows(session, ref winMech);
        }
        NativeCULong rv = _delegates.C_DigestInit(session, ref mechanism);
        return rv.ToCKR();
    }

    /// <summary>
    /// Digests data in a single part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be digested</param>
    /// <param name="dataLen">The length of the data to be digested</param>
    /// <param name="digest">
    /// If set to null then the length of digest is returned in "digestLen" parameter, without actually returning digest.
    /// If not set to null then "digestLen" parameter must contain the lenght of digest array and digest is returned in "digest" parameter.
    /// </param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? digest, ref NativeCULong digestLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Digest(session, data, dataLen, digest, ref digestLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <param name="partLen">The length of the data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestUpdate(session, part, partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part message-digesting operation by digesting the value of a secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="key">The handle of the secret key to be digested</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE, CKR_KEY_SIZE_RANGE, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestKey(NativeCULong session, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestKey(session, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part message-digesting operation, returning the message digest
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="digest">
    /// If set to null then the length of digest is returned in "digestLen" parameter, without actually returning digest.
    /// If not set to null then "digestLen" parameter must contain the lenght of digest array and digest is returned in "digest" parameter.
    /// </param>
    /// <param name="digestLen">Location that holds the length of the message digest</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestFinal(session, digest, ref digestLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a signature operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="key">Handle of the signature key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED,CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_SignInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_SignInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_SignInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Signs data in a single part, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="dataLen">The length of the data</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public CKR C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Sign(session, data, dataLen, signature, ref signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part signature operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <param name="partLen">The length of the data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignUpdate(session, part, partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part signature operation, returning the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_REJECTED</returns>
    public CKR C_SignFinal(NativeCULong session, byte[]? signature, ref NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignFinal(session, signature, ref signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a signature operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="key">Handle of the signature key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_SignRecoverInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_SignRecoverInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_SignRecoverInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Signs data in a single operation, where the data can be recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="dataLen">The length of data to be signed</param>
    /// <param name="signature">
    /// If set to null then the length of signature is returned in "signatureLen" parameter, without actually returning signature.
    /// If not set to null then "signatureLen" parameter must contain the lenght of signature array and signature is returned in "signature" parameter.
    /// </param>
    /// <param name="signatureLen">Location that holds the length of the signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignRecover(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignRecover(session, data, dataLen, signature, ref signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a verification operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">The verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_VerifyInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_VerifyInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_VerifyInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the signature is an appendix to the data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="data">Data that were signed</param>
    /// <param name="dataLen">The length of the data</param>
    /// <param name="signature">Signature of data</param>
    /// <param name="signatureLen">The length of signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public CKR C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_Verify(session, data, dataLen, signature, signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">Data part</param>
    /// <param name="partLen">The length of the data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyUpdate(session, part, partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Finishes a multi-part verification operation, checking the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <param name="signatureLen">The length of signature</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE</returns>
    public CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyFinal(session, signature, signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Initializes a signature verification operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Verification mechanism</param>
    /// <param name="key">The handle of the verification key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_VerifyRecoverInit_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_VerifyRecoverInit_Windows(session, ref winMech, key);
        }
        NativeCULong rv = _delegates.C_VerifyRecoverInit(session, ref mechanism, key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Verifies a signature in a single-part operation, where the data is recovered from the signature
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="signature">Signature</param>
    /// <param name="signatureLen">The length of signature</param>
    /// <param name="data">
    /// If set to null then the length of recovered data is returned in "dataLen" parameter, without actually returning recovered data.
    /// If not set to null then "dataLen" parameter must contain the lenght of data array and recovered data is returned in "data" parameter.
    /// </param>
    /// <param name="dataLen">Location that holds the length of the decrypted data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID</returns>
    public CKR C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[]? data, ref NativeCULong dataLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_VerifyRecover(session, signature, signatureLen, data, ref dataLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues multi-part digest and encryption operations, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be digested and encrypted</param>
    /// <param name="partLen">Length of data part in bytes</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DigestEncryptUpdate(session, part, partLen, encryptedPart, ref encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined decryption and digest operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="encryptedPartLen">Length of the encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptDigestUpdate(session, encryptedPart, encryptedPartLen, part, ref partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined signature and encryption operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="part">The data part to be signed and encrypted</param>
    /// <param name="partLen">Length of data part in bytes</param>
    /// <param name="encryptedPart">
    /// If set to null then the length of encrypted data part is returned in "encryptedPartLen" parameter, without actually returning encrypted data part.
    /// If not set to null then "encryptedPartLen" parameter must contain the lenght of encryptedPart array and encrypted data part is returned in "encryptedPart" parameter.
    /// </param>
    /// <param name="encryptedPartLen">Location that holds the length in bytes of the encrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SignEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SignEncryptUpdate(session, part, partLen, encryptedPart, ref encryptedPartLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Continues a multi-part combined decryption and verification operation, processing another data part
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="encryptedPart">Encrypted data part</param>
    /// <param name="encryptedPartLen">Length of the encrypted data part</param>
    /// <param name="part">
    /// If set to null then the length of decrypted data part is returned in "partLen" parameter, without actually returning decrypted data part.
    /// If not set to null then "partLen" parameter must contain the lenght of part array and decrypted data part is returned in "part" parameter.
    /// </param>
    /// <param name="partLen">Location that holds the length of the decrypted data part</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DecryptVerifyUpdate(session, encryptedPart, encryptedPartLen, part, ref partLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="template">The template for the new key or set of domain parameters</param>
    /// <param name="count">The number of attributes in the template</param>
    /// <param name="key">Location that receives the handle of the new key or set of domain parameters</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GenerateKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_GenerateKey_Windows(session, ref winMech, winTpl, count, ref key);
        }
        NativeCULong rv = _delegates.C_GenerateKey(session, ref mechanism, template, count, ref key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Generates a public/private key pair, creating new key objects
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="publicKeyTemplate">The template for the public key</param>
    /// <param name="publicKeyAttributeCount">The number of attributes in the public-key template</param>
    /// <param name="privateKeyTemplate">The template for the private key</param>
    /// <param name="privateKeyAttributeCount">The number of attributes in the private-key template</param>
    /// <param name="publicKey">Location that receives the handle of the new public key</param>
    /// <param name="privateKey">Location that receives the handle of the new private key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[]? privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_GenerateKeyPair_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winPubTpl = publicKeyTemplate is null ? null! : System.Array.ConvertAll(publicKeyTemplate, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            var winPrivTpl = privateKeyTemplate is null ? null! : System.Array.ConvertAll(privateKeyTemplate, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_GenerateKeyPair_Windows(session, ref winMech, winPubTpl, publicKeyAttributeCount, winPrivTpl, privateKeyAttributeCount, ref publicKey, ref privateKey);
        }
        NativeCULong rv = _delegates.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, publicKeyAttributeCount, privateKeyTemplate, privateKeyAttributeCount, ref publicKey, ref privateKey);
        return rv.ToCKR();
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKey">The handle of the wrapping key</param>
    /// <param name="key">The handle of the key to be wrapped</param>
    /// <param name="wrappedKey">
    /// If set to null then the length of wrapped key is returned in "wrappedKeyLen" parameter, without actually returning wrapped key.
    /// If not set to null then "wrappedKeyLen" parameter must contain the lenght of wrappedKey array and wrapped key is returned in "wrappedKey" parameter.
    /// </param>
    /// <param name="wrappedKeyLen">Location that receives the length of the wrapped key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_NOT_WRAPPABLE, CKR_KEY_SIZE_RANGE, CKR_KEY_UNEXTRACTABLE, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN, CKR_WRAPPING_KEY_HANDLE_INVALID, CKR_WRAPPING_KEY_SIZE_RANGE, CKR_WRAPPING_KEY_TYPE_INCONSISTENT</returns>
    public CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_WrapKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return (CKR)(ulong)_delegates.C_WrapKey_Windows(session, ref winMech, wrappingKey, key, wrappedKey, ref wrappedKeyLen);
        }
        NativeCULong rv = _delegates.C_WrapKey(session, ref mechanism, wrappingKey, key, wrappedKey, ref wrappedKeyLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Unwrapping mechanism</param>
    /// <param name="unwrappingKey">The handle of the unwrapping key</param>
    /// <param name="wrappedKey">Wrapped key</param>
    /// <param name="wrappedKeyLen">The length of the wrapped key</param>
    /// <param name="template">The template for the new key</param>
    /// <param name="attributeCount">The number of attributes in the template</param>
    /// <param name="key">Location that receives the handle of the unwrapped key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_SIZE_RANGE, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR_USER_NOT_LOGGED_IN, CKR_WRAPPED_KEY_INVALID, CKR_WRAPPED_KEY_LEN_RANGE</returns>
    public CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_UnwrapKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_UnwrapKey_Windows(session, ref winMech, unwrappingKey, wrappedKey, wrappedKeyLen, winTpl, attributeCount, ref key);
        }
        NativeCULong rv = _delegates.C_UnwrapKey(session, ref mechanism, unwrappingKey, wrappedKey, wrappedKeyLen, template, attributeCount, ref key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="mechanism">Key derivation mechanism</param>
    /// <param name="baseKey">The handle of the base key</param>
    /// <param name="template">The template for the new key</param>
    /// <param name="attributeCount">The number of attributes in the template</param>
    /// <param name="key">Location that receives the handle of the derived key</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (Pkcs11Marshal.IsWindows && _delegates!.HasC_DeriveKey_Windows)
        {
            var winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            var winTpl = template is null ? null! : System.Array.ConvertAll(template, static a => CK_ATTRIBUTE_Windows.FromUnified(in a));
            return (CKR)(ulong)_delegates.C_DeriveKey_Windows(session, ref winMech, baseKey, winTpl, attributeCount, ref key);
        }
        NativeCULong rv = _delegates.C_DeriveKey(session, ref mechanism, baseKey, template, attributeCount, ref key);
        return rv.ToCKR();
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="seed">The seed material</param>
    /// <param name="seedLen">The length of the seed material</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_SeedRandom(session, seed, seedLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="randomData">Location that receives the random data</param>
    /// <param name="randomLen">The length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GenerateRandom(session, randomData, randomLen);
        return rv.ToCKR();
    }

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

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur
    /// </summary>
    /// <param name="flags">Determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits for a slot event to occur)</param>
    /// <param name="slot">Location which will receive the ID of the slot that the event occurred in</param>
    /// <param name="reserved">Reserved for future versions (should be null)</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NO_EVENT, CKR_OK</returns>
    public CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_WaitForSlotEvent(flags, ref slot, reserved);
        return rv.ToCKR();
    }


    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _library.Dispose();
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~LowLevelPkcs11Library()
    {
        Dispose(false);
    }
}