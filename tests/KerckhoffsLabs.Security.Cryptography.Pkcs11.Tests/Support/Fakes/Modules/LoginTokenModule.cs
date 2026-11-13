using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

/// <summary>
/// One token in slot 0 that follows the login rules of PKCS#11 v3.2 (session_mgmt_functions.md) for a
/// single application: one login state shared by all its sessions, set by <c>C_Login</c> or
/// <c>C_LoginUser</c> on any of them and cleared by <c>C_Logout</c> or by closing the last session.
/// </summary>
/// <remarks>
/// <para>
/// Modelled: <c>CKR_USER_ALREADY_LOGGED_IN</c> for the same user (and username), checked before the PIN as
/// tokens commonly do, so a second login is not a second authentication;
/// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c> for any other; <c>CKR_SESSION_READ_ONLY_EXISTS</c> for an SO
/// login while a read-only session is open; <c>CKR_SESSION_READ_WRITE_SO_EXISTS</c> for a read-only session
/// while the SO is logged in; <c>CKR_TOKEN_WRITE_PROTECTED</c> for a read/write session on a
/// <see cref="WriteProtected"/> token; and the five <c>CKS_*</c> session states.
/// </para>
/// <para>
/// State is guarded by one lock, so tests may call from several threads.
/// </para>
/// </remarks>
internal sealed class LoginTokenModule : FakeModule
{
    /// <summary>The token's only slot.</summary>
    public const ulong SlotId = 0;

    /// <summary>The label <c>C_GetTokenInfo</c> reports.</summary>
    public const string TokenLabel = "login-token";

    private readonly Lock _lock = new();
    private readonly List<(ulong Handle, bool ReadWrite)> _sessions = [];
    private CKU? _loggedIn;
    private byte[]? _username;
    private int _loginCalls;
    private int _logoutCalls;

    /// <summary>The PIN <c>C_Login</c> accepts, for every user type; anything else is <c>CKR_PIN_INCORRECT</c>.</summary>
    public byte[] ExpectedPin { get; set; } = "1234"u8.ToArray();

    /// <summary>Whether the token reports <c>CKF_WRITE_PROTECTED</c> and refuses read/write sessions.</summary>
    public bool WriteProtected { get; set; }

    /// <summary>
    /// Runs at the start of every <c>C_Login</c> and <c>C_LoginUser</c>, before the token's lock, with the session
    /// handle: lets a test block a login in flight or act while one is.
    /// </summary>
    public Action<NativeCULong>? DuringLogin { get; set; }

    /// <summary>
    /// Runs inside every <c>C_Sign</c> that produces a signature (not a length probe), before the token's
    /// lock: lets a test hold an operation in flight. <c>C_SignInit</c> accepts any mechanism and key.
    /// </summary>
    public Action? DuringSign { get; set; }

    /// <summary>The length of the signature <c>C_Sign</c> produces.</summary>
    public const int SignatureLength = 32;

    /// <summary>Who the application is logged in as, or <see langword="null"/> when its sessions are public.</summary>
    public CKU? LoggedIn
    {
        get { lock (_lock) return _loggedIn; }
    }

    /// <summary>Calls to <c>C_Login</c> and <c>C_LoginUser</c>, whatever they answered.</summary>
    public int LoginCalls
    {
        get { lock (_lock) return _loginCalls; }
    }

    /// <summary>Calls to <c>C_Logout</c>, whatever they answered.</summary>
    public int LogoutCalls
    {
        get { lock (_lock) return _logoutCalls; }
    }

    /// <summary>A snapshot of the open sessions, in the order they were opened.</summary>
    public IReadOnlyList<(ulong Handle, bool ReadWrite)> OpenSessions
    {
        get { lock (_lock) return [.. _sessions]; }
    }

    protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
    {
        if (slotList.IsNull) { count = (NativeCULong)1; return CKR.CKR_OK; }
        if (slotList.Span.Length < 1) { count = (NativeCULong)1; return CKR.CKR_BUFFER_TOO_SMALL; }
        slotList.Span[0] = (NativeCULong)SlotId;
        count = (NativeCULong)1;
        return CKR.CKR_OK;
    }

    protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        if ((ulong)slotId != SlotId)
            return CKR.CKR_SLOT_ID_INVALID;
        NativeTestStructs.FillPadded(info.Label, TokenLabel);
        ulong flags = CKF.CKF_LOGIN_REQUIRED | CKF.CKF_USER_PIN_INITIALIZED | CKF.CKF_TOKEN_INITIALIZED;
        if (WriteProtected)
            flags |= CKF.CKF_WRITE_PROTECTED;
        info.Flags = (NativeCULong)flags;
        lock (_lock)
        {
            info.SessionCount = (NativeCULong)(ulong)_sessions.Count;
            info.RwSessionCount = (NativeCULong)(ulong)_sessions.Count(s => s.ReadWrite);
        }
        return CKR.CKR_OK;
    }

    protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        if ((ulong)slotId != SlotId)
            return CKR.CKR_SLOT_ID_INVALID;
        if (((ulong)flags & CKF.CKF_SERIAL_SESSION) == 0)
            return CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        bool readWrite = ((ulong)flags & CKF.CKF_RW_SESSION) != 0;
        lock (_lock)
        {
            if (readWrite && WriteProtected)
                return CKR.CKR_TOKEN_WRITE_PROTECTED;
            if (!readWrite && _loggedIn == CKU.CKU_SO)
                return CKR.CKR_SESSION_READ_WRITE_SO_EXISTS;
            NativeCULong handle = NewSessionHandle();
            _sessions.Add(((ulong)handle, readWrite));
            session = handle;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_CloseSession(NativeCULong session)
    {
        lock (_lock)
        {
            int index = _sessions.FindIndex(s => s.Handle == (ulong)session);
            if (index < 0)
                return CKR.CKR_SESSION_HANDLE_INVALID;
            _sessions.RemoveAt(index);

            // Closing the last session returns the application to public sessions.
            if (_sessions.Count == 0)
                LogOutLocked();
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
    {
        DuringLogin?.Invoke(session);
        lock (_lock)
        {
            _loginCalls++;
            return LoginLocked(session, (CKU)(ulong)userType, pin, username: null);
        }
    }

    protected override CKR C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        DuringLogin?.Invoke(session);
        lock (_lock)
        {
            _loginCalls++;
            return LoginLocked(session, (CKU)(ulong)userType, pin, username.ToArray());
        }
    }

    protected override CKR C_Logout(NativeCULong session)
    {
        lock (_lock)
        {
            _logoutCalls++;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (_loggedIn is null)
                return CKR.CKR_USER_NOT_LOGGED_IN;
            LogOutLocked();
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
    {
        lock (_lock)
            return IsOpen(session) ? CKR.CKR_OK : CKR.CKR_SESSION_HANDLE_INVALID;
    }

    protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
    {
        if (!signature.IsNull)
            DuringSign?.Invoke();
        lock (_lock)
        {
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (!signature.IsNull)
            {
                if (signature.Span.Length < SignatureLength)
                {
                    signatureLen = (NativeCULong)(ulong)SignatureLength;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                signature.Span[..SignatureLength].Fill(0x5A);
            }
            signatureLen = (NativeCULong)(ulong)SignatureLength;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        lock (_lock)
        {
            int index = _sessions.FindIndex(s => s.Handle == (ulong)session);
            if (index < 0)
                return CKR.CKR_SESSION_HANDLE_INVALID;
            bool readWrite = _sessions[index].ReadWrite;
            CKS state = (_loggedIn, readWrite) switch
            {
                (CKU.CKU_SO, _) => CKS.CKS_RW_SO_FUNCTIONS,
                (CKU.CKU_USER, true) => CKS.CKS_RW_USER_FUNCTIONS,
                (CKU.CKU_USER, false) => CKS.CKS_RO_USER_FUNCTIONS,
                (_, true) => CKS.CKS_RW_PUBLIC_SESSION,
                (_, false) => CKS.CKS_RO_PUBLIC_SESSION,
            };
            info.SlotId = (NativeCULong)SlotId;
            info.State = (NativeCULong)(ulong)state;
            info.Flags = (NativeCULong)(CKF.CKF_SERIAL_SESSION | (readWrite ? CKF.CKF_RW_SESSION : 0));
            info.DeviceError = default;
            return CKR.CKR_OK;
        }
    }

    // The order of the checks follows C_Login's description: the session, the user type, the
    // existing login (same user, then another), the SO/read-only exclusion, then the PIN.
    private CKR LoginLocked(NativeCULong session, CKU userType, ReadOnlySpan<byte> pin, byte[]? username)
    {
        if (!IsOpen(session))
            return CKR.CKR_SESSION_HANDLE_INVALID;
        if (userType == CKU.CKU_CONTEXT_SPECIFIC)
            return CKR.CKR_OPERATION_NOT_INITIALIZED; // this fake starts no operations
        if (userType is not (CKU.CKU_SO or CKU.CKU_USER))
            return CKR.CKR_USER_TYPE_INVALID;
        if (_loggedIn is { } held)
        {
            bool sameUser = held == userType && SameUsername(_username, username);
            return sameUser ? CKR.CKR_USER_ALREADY_LOGGED_IN : CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
        }
        if (userType == CKU.CKU_SO && _sessions.Exists(s => !s.ReadWrite))
            return CKR.CKR_SESSION_READ_ONLY_EXISTS;
        if (!pin.SequenceEqual(ExpectedPin))
            return CKR.CKR_PIN_INCORRECT;
        _loggedIn = userType;
        _username = username;
        return CKR.CKR_OK;
    }

    private static bool SameUsername(byte[]? held, byte[]? asked)
        => held is null ? asked is null : asked is not null && held.AsSpan().SequenceEqual(asked);

    private bool IsOpen(NativeCULong session) => _sessions.Exists(s => s.Handle == (ulong)session);

    private void LogOutLocked()
    {
        _loggedIn = null;
        _username = null;
    }
}
