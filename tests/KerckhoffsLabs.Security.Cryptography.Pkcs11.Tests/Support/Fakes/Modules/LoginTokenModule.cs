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
/// <see cref="WriteProtected"/> token; <c>CKR_SESSION_COUNT</c> for a session beyond <see cref="MaxSessions"/> or
/// a read/write one beyond <see cref="MaxRwSessions"/>; <c>CKR_SESSION_EXISTS</c> for <c>C_InitToken</c> while a
/// session is open; and the five <c>CKS_*</c> session states.
/// </para>
/// <para>
/// Objects (<see cref="AddObject"/>, <c>C_CreateObject</c>, and the key-creating functions <c>C_GenerateKey</c>,
/// <c>C_GenerateKeyPair</c>, <c>C_UnwrapKey</c>, <c>C_DeriveKey</c>, <c>C_EncapsulateKey</c> and
/// <c>C_DecapsulateKey</c>) answer <c>C_FindObjects*</c> and <c>C_GetAttributeValue</c>, and <c>C_DestroyObject</c>
/// removes them. One made without <c>CKA_TOKEN</c> true is a session object (its <c>CKA_TOKEN</c> reads false): closing the session that created it
/// destroys it, as <c>C_CloseSession</c> requires. A private object (<c>CKA_PRIVATE</c> true) is visible only while the application
/// is logged in, and <c>C_Logout</c> invalidates its handle "even if a user is later logged back into the token":
/// it is given a new handle, so the old one answers <c>CKR_OBJECT_HANDLE_INVALID</c> for good.
/// </para>
/// <para>
/// <see cref="FailSession"/> makes every later call on one session fail with a given code, as a removed device
/// would, until the session is closed.
/// </para>
/// <para>
/// Sign and decrypt operations are tracked per session, as PKCS#11 v3.2 requires: a second <c>C_SignInit</c> or
/// <c>C_DecryptInit</c> while one is active answers <c>CKR_OPERATION_ACTIVE</c>, and <c>C_SessionCancel</c> ends
/// them (unless <see cref="SupportsSessionCancel"/> is false). A private key with <c>CKA_ALWAYS_AUTHENTICATE</c> true (private_key_objects.md) needs a
/// <c>C_Login(CKU_CONTEXT_SPECIFIC)</c> with <see cref="ExpectedPin"/> (or a NULL PIN, the pinpad) after its
/// <c>C_*Init</c>, else <c>C_Sign</c> and <c>C_Decrypt</c> answer <c>CKR_USER_NOT_LOGGED_IN</c>. A wrong PIN
/// answers <c>CKR_PIN_INCORRECT</c> and leaves the operation as it was; the <see cref="LockAfter"/>-th wrong one in a
/// row answers <c>CKR_PIN_LOCKED</c> and logs the application out. A context login with no such operation answers
/// <c>CKR_OPERATION_NOT_INITIALIZED</c>. <see cref="CallLog"/> records the order of these calls.
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
    private readonly List<CKR> _openSessionResults = [];
    private CKU? _loggedIn;
    private byte[]? _username;
    private int _loginCalls;
    private int _logoutCalls;
    private int _initTokenCalls;
    private (ulong Session, byte[] Pin)? _lastInitPin;
    private (ulong Session, byte[] OldPin, byte[] NewPin)? _lastSetPin;
    private readonly Dictionary<ulong, Dictionary<CKA, byte[]>> _objects = [];

    // The session objects (CKA_TOKEN false) and the session that created each: its C_CloseSession destroys them.
    private readonly Dictionary<ulong, ulong> _sessionObjects = [];
    private readonly Dictionary<ulong, Queue<ulong>> _finds = [];
    private readonly Dictionary<ulong, CKR> _failing = [];
    private ulong _nextObject = 0x100;
    private readonly Dictionary<(ulong Session, ulong Kind), ActiveOperation> _operations = [];
    private readonly List<string> _callLog = [];
    private readonly List<byte[]> _contextPins = [];
    private int _wrongContextPins;

    // An operation begun by C_SignInit or C_DecryptInit, and whether its key needs, and has had, a context login.
    private sealed class ActiveOperation(bool alwaysAuthenticate)
    {
        public bool AlwaysAuthenticate { get; } = alwaysAuthenticate;
        public bool Authenticated { get; set; }
    }

    /// <summary>The <c>C_Login(CKU_CONTEXT_SPECIFIC)</c> entry of <see cref="CallLog"/>.</summary>
    public const string ContextLogin = "C_Login(CKU_CONTEXT_SPECIFIC)";

    /// <summary>
    /// The sign and decrypt calls, in order: <c>C_SignInit</c>, <c>C_Sign</c>, <c>C_DecryptInit</c>,
    /// <c>C_Decrypt</c>, <see cref="ContextLogin"/> and <c>C_SessionCancel</c>.
    /// </summary>
    public IReadOnlyList<string> CallLog
    {
        get { lock (_lock) return [.. _callLog]; }
    }

    private readonly List<ulong> _destroyObjectCalls = [];

    /// <summary>The handles <c>C_DestroyObject</c> was called for, in order, whatever it answered.</summary>
    public IReadOnlyList<ulong> DestroyObjectCalls
    {
        get { lock (_lock) return [.. _destroyObjectCalls]; }
    }

    /// <summary>Empties <see cref="CallLog"/>.</summary>
    public void ClearCallLog()
    {
        lock (_lock)
            _callLog.Clear();
    }

    /// <summary>The PIN of every context login that reached an operation, in order; empty for a pinpad (NULL) one.</summary>
    public IReadOnlyList<byte[]> ContextPins
    {
        get { lock (_lock) return [.. _contextPins]; }
    }

    /// <summary>How many wrong context-login PINs in a row lock the PIN (<c>CKR_PIN_LOCKED</c>).</summary>
    public int LockAfter { get; set; } = 3;

    /// <summary>Whether a sign or decrypt operation is active on <paramref name="session"/>.</summary>
    public bool HasActiveOperation(ulong session)
    {
        lock (_lock)
            return _operations.Keys.Any(k => k.Session == session);
    }

    /// <summary>The PIN <c>C_Login</c> accepts, for every user type; anything else is <c>CKR_PIN_INCORRECT</c>.</summary>
    public byte[] ExpectedPin { get; set; } = "1234"u8.ToArray();

    /// <summary>Whether the token reports <c>CKF_WRITE_PROTECTED</c> and refuses read/write sessions.</summary>
    public bool WriteProtected { get; set; }

    /// <summary>
    /// How many sessions the application may have open at once, or <see langword="null"/> for no limit: one more
    /// is <c>CKR_SESSION_COUNT</c> (PKCS#11 v3.2 C_OpenSession).
    /// </summary>
    public int? MaxSessions { get; set; }

    /// <summary>
    /// How many read/write sessions the application may have open at once, or <see langword="null"/> for no limit:
    /// one more is <c>CKR_SESSION_COUNT</c>; a read-only one still opens within <see cref="MaxSessions"/>.
    /// </summary>
    public int? MaxRwSessions { get; set; }

    /// <summary>
    /// Whether <c>C_GetTokenInfo</c> reports <see cref="MaxSessions"/> and <see cref="MaxRwSessions"/> in
    /// <c>ulMaxSessionCount</c> and <c>ulMaxRwSessionCount</c> (<c>CK_EFFECTIVELY_INFINITE</c> for no limit).
    /// <see langword="false"/> reports <c>CK_EFFECTIVELY_INFINITE</c> whatever the limit, as pkcs11-mock does: the
    /// fields are optional, so only <c>C_OpenSession</c>'s answer tells.
    /// </summary>
    public bool ReportSessionLimits { get; set; } = true;

    /// <summary>Every <c>C_OpenSession</c> answer, in order.</summary>
    public IReadOnlyList<CKR> OpenSessionResults
    {
        get { lock (_lock) return [.. _openSessionResults]; }
    }

    /// <summary>
    /// Runs at the start of every <c>C_Login</c> and <c>C_LoginUser</c>, before the token's lock, with the session
    /// handle: lets a test block a login in flight or act while one is.
    /// </summary>
    public Action<NativeCULong>? DuringLogin { get; set; }

    /// <summary>
    /// Runs at the start of every <c>C_GetSessionInfo</c>, before the token's lock, with the session handle: lets a test
    /// block the login record's probe of its anchor in flight.
    /// </summary>
    public Action<NativeCULong>? DuringGetSessionInfo { get; set; }

    /// <summary>
    /// Runs at the start of every <c>C_Logout</c>, before the token's lock, with the session handle: lets a test hold a
    /// logout in flight.
    /// </summary>
    public Action<NativeCULong>? DuringLogout { get; set; }

    /// <summary>The label <c>C_GetTokenInfo</c> reports; <see cref="TokenLabel"/> unless a test swaps the token.</summary>
    public string Label { get; set; } = TokenLabel;

    // Results the next calls of a function answer instead of doing anything, in order (FailNext).
    private readonly Dictionary<string, Queue<CKR>> _failNext = [];

    /// <summary>
    /// Makes the next call of <paramref name="function"/> (<c>"C_OpenSession"</c>, <c>"C_Login"</c>, <c>"C_Logout"</c>
    /// or <c>"C_GetSessionInfo"</c>) answer <paramref name="rv"/> and do nothing else; queued, one call each.
    /// </summary>
    public void FailNext(string function, CKR rv)
    {
        lock (_lock)
        {
            if (!_failNext.TryGetValue(function, out Queue<CKR>? queue))
                _failNext[function] = queue = new Queue<CKR>();
            queue.Enqueue(rv);
        }
    }

    // Under _lock. The queued failure for function, if any.
    private bool FailsNextLocked(string function, out CKR rv)
    {
        rv = CKR.CKR_OK;
        return _failNext.TryGetValue(function, out Queue<CKR>? queue) && queue.TryDequeue(out rv);
    }

    /// <summary>
    /// The module drops the application's login on its own (an idle timeout, another component's <c>C_Logout</c>):
    /// logged out, its private handles renumbered, every session left open.
    /// </summary>
    public void DropLogin()
    {
        lock (_lock)
            LogOutLocked();
    }

    /// <summary>
    /// Runs inside every <c>C_Sign</c> that produces a signature (not a length probe), before the token's
    /// lock: lets a test hold an operation in flight. <c>C_SignInit</c> accepts any mechanism and key.
    /// </summary>
    public Action? DuringSign { get; set; }

    /// <summary>
    /// Runs at the start of every <c>C_FindObjectsInit</c>, before the token's lock: lets a test act while a search
    /// is in flight.
    /// </summary>
    public Action? DuringFind { get; set; }

    /// <summary>
    /// Runs at the start of every <c>C_GetAttributeValue</c>, before the token's lock, with the object handle: lets a
    /// test observe what else is going on while an object is read.
    /// </summary>
    public Action<ulong>? DuringGetAttributeValue { get; set; }

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

    /// <summary>Calls to <c>C_InitToken</c>, whatever they answered.</summary>
    public int InitTokenCalls
    {
        get { lock (_lock) return _initTokenCalls; }
    }

    /// <summary>
    /// Puts an object on the token and returns its handle. A private one is visible only while logged in, and
    /// gets a new handle at every logout.
    /// </summary>
    public ulong AddObject(CKO objectClass, string label, bool isPrivate, CKK? keyType = null, byte[]? value = null,
        IReadOnlyDictionary<CKA, byte[]>? more = null)
    {
        var attributes = new Dictionary<CKA, byte[]>
        {
            [CKA.CKA_CLASS] = Ulong((ulong)objectClass),
            [CKA.CKA_LABEL] = System.Text.Encoding.UTF8.GetBytes(label),
            [CKA.CKA_ID] = [],
            [CKA.CKA_PRIVATE] = [isPrivate ? (byte)1 : (byte)0],
        };
        if (keyType is { } type)
            attributes[CKA.CKA_KEY_TYPE] = Ulong((ulong)type);
        if (value is not null)
            attributes[CKA.CKA_VALUE] = value;
        foreach ((CKA attribute, byte[] bytes) in more ?? new Dictionary<CKA, byte[]>())
            attributes[attribute] = bytes;
        lock (_lock)
        {
            ulong handle = _nextObject++;
            _objects[handle] = attributes;
            return handle;
        }
    }

    /// <summary>Whether the token holds an object with handle <paramref name="handle"/>, visible or not.</summary>
    public bool HasObject(ulong handle)
    {
        lock (_lock)
            return _objects.ContainsKey(handle);
    }

    /// <summary>
    /// Whether <c>C_SessionCancel</c> works. <see langword="false"/> answers <c>CKR_FUNCTION_NOT_SUPPORTED</c> and
    /// leaves the operations active, as on a module from before v3.0 (pkcs11-mock).
    /// </summary>
    public bool SupportsSessionCancel { get; set; } = true;

    /// <summary>
    /// Makes every later call on <paramref name="session"/> answer <paramref name="rv"/> (say
    /// <c>CKR_DEVICE_REMOVED</c>), until the session is closed.
    /// </summary>
    public void FailSession(ulong session, CKR rv)
    {
        lock (_lock)
            _failing[session] = rv;
    }

    /// <summary>
    /// The token pulled and put back, or a network HSM failing over: every session open now answers
    /// <paramref name="rv"/> to every later call until it is closed, and the application is logged out. Private
    /// object handles stay as they were: the test checks the library refuses them, not the module.
    /// </summary>
    public void ReinsertToken(CKR rv = CKR.CKR_DEVICE_REMOVED)
    {
        lock (_lock)
        {
            foreach ((ulong handle, _) in _sessions)
                _failing[handle] = rv;
            _loggedIn = null;
            _username = null;
        }
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
        NativeTestStructs.FillPadded(info.Label, Label);
        ulong flags = CKF.CKF_LOGIN_REQUIRED | CKF.CKF_USER_PIN_INITIALIZED | CKF.CKF_TOKEN_INITIALIZED;
        if (WriteProtected)
            flags |= CKF.CKF_WRITE_PROTECTED;
        info.Flags = (NativeCULong)flags;
        lock (_lock)
        {
            info.SessionCount = (NativeCULong)(ulong)_sessions.Count;
            info.RwSessionCount = (NativeCULong)(ulong)_sessions.Count(s => s.ReadWrite);
        }
        info.MaxSessionCount = (NativeCULong)Reported(MaxSessions);
        info.MaxRwSessionCount = (NativeCULong)Reported(MaxRwSessions);
        return CKR.CKR_OK;
    }

    protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        lock (_lock)
        {
            CKR rv = FailsNextLocked("C_OpenSession", out CKR failure) ? failure : OpenSessionLocked(slotId, flags, ref session);
            _openSessionResults.Add(rv);
            return rv;
        }
    }

    private CKR OpenSessionLocked(NativeCULong slotId, NativeCULong flags, ref NativeCULong session)
    {
        if ((ulong)slotId != SlotId)
            return CKR.CKR_SLOT_ID_INVALID;
        if (((ulong)flags & CKF.CKF_SERIAL_SESSION) == 0)
            return CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        bool readWrite = ((ulong)flags & CKF.CKF_RW_SESSION) != 0;
        if (readWrite && WriteProtected)
            return CKR.CKR_TOKEN_WRITE_PROTECTED;
        if (!readWrite && _loggedIn == CKU.CKU_SO)
            return CKR.CKR_SESSION_READ_WRITE_SO_EXISTS;
        if (_sessions.Count >= MaxSessions || (readWrite && _sessions.Count(s => s.ReadWrite) >= MaxRwSessions))
            return CKR.CKR_SESSION_COUNT;
        NativeCULong handle = NewSessionHandle();
        _sessions.Add(((ulong)handle, readWrite));
        session = handle;
        return CKR.CKR_OK;
    }

    private ulong Reported(int? limit)
        => ReportSessionLimits && limit is { } max ? (ulong)max : CK.CK_EFFECTIVELY_INFINITE;

    protected override CKR C_CloseSession(NativeCULong session)
    {
        lock (_lock)
        {
            int index = _sessions.FindIndex(s => s.Handle == (ulong)session);
            if (index < 0)
                return CKR.CKR_SESSION_HANDLE_INVALID;
            _sessions.RemoveAt(index);
            _failing.Remove((ulong)session);
            _finds.Remove((ulong)session);
            EndOperationsLocked((ulong)session, CKF.CKF_SIGN | CKF.CKF_DECRYPT);
            foreach (ulong created in _sessionObjects.Where(o => o.Value == (ulong)session).Select(o => o.Key).ToList())
            {
                _sessionObjects.Remove(created);
                _objects.Remove(created);
            }

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
            if (FailsNextLocked("C_Login", out CKR next))
                return next;
            if ((CKU)(ulong)userType == CKU.CKU_CONTEXT_SPECIFIC)
                _callLog.Add(ContextLogin);
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            return LoginLocked(session, (CKU)(ulong)userType, pin, username: null);
        }
    }

    protected override CKR C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
    {
        DuringLogin?.Invoke(session);
        lock (_lock)
        {
            _loginCalls++;
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            return LoginLocked(session, (CKU)(ulong)userType, pin, username.ToArray());
        }
    }

    /// <summary>
    /// The last <c>C_InitPIN</c> that succeeded: the session it came on and the PIN (empty for the protected
    /// authentication path), or <see langword="null"/> when none has.
    /// </summary>
    public (ulong Session, byte[] Pin)? LastInitPin
    {
        get { lock (_lock) return _lastInitPin; }
    }

    /// <summary>The last <c>C_SetPIN</c> that succeeded: the session and both PINs (empty for a pinpad).</summary>
    public (ulong Session, byte[] OldPin, byte[] NewPin)? LastSetPin
    {
        get { lock (_lock) return _lastSetPin; }
    }

    // PKCS#11 v3.2 C_InitPIN: only in the "R/W SO Functions" state, else CKR_USER_NOT_LOGGED_IN.
    protected override CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin)
    {
        lock (_lock)
        {
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            int index = _sessions.FindIndex(s => s.Handle == (ulong)session);
            if (index < 0)
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (_loggedIn != CKU.CKU_SO || !_sessions[index].ReadWrite)
                return CKR.CKR_USER_NOT_LOGGED_IN;
            _lastInitPin = ((ulong)session, pin.ToArray());
            return CKR.CKR_OK;
        }
    }

    // PKCS#11 v3.2 C_SetPIN: only in "R/W Public", "R/W SO Functions" or "R/W User Functions", else
    // CKR_SESSION_READ_ONLY. The fake checks no PINs.
    protected override CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        lock (_lock)
        {
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            int index = _sessions.FindIndex(s => s.Handle == (ulong)session);
            if (index < 0)
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (!_sessions[index].ReadWrite)
                return CKR.CKR_SESSION_READ_ONLY;
            _lastSetPin = ((ulong)session, oldPin.ToArray(), newPin.ToArray());
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_Logout(NativeCULong session)
    {
        DuringLogout?.Invoke(session);
        lock (_lock)
        {
            _logoutCalls++;
            if (FailsNextLocked("C_Logout", out CKR next))
                return next;
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (_loggedIn is null)
                return CKR.CKR_USER_NOT_LOGGED_IN;
            LogOutLocked();
            return CKR.CKR_OK;
        }
    }

    // Any mechanism; any key the token does not know (the tests that sign with a made-up handle), but not an
    // object it knows and the session cannot see.
    protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        => BeginOperation(session, key, CKF.CKF_SIGN, "C_SignInit");

    // Verify, encrypt and decrypt accept any mechanism and key, like sign: every signature verifies, and the
    // ciphers copy their input.
    protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitOn(session, key);

    protected override CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        lock (_lock)
            return IsOpen(session) ? CKR.CKR_OK : CKR.CKR_SESSION_HANDLE_INVALID;
    }

    protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitOn(session, key);

    protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        => Copy(session, data, encryptedData, ref encryptedDataLen);

    protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        => BeginOperation(session, key, CKF.CKF_DECRYPT, "C_DecryptInit");

    protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
    {
        lock (_lock)
        {
            _callLog.Add("C_Decrypt");
            CKR rv = UseOperationLocked((ulong)session, CKF.CKF_DECRYPT);
            if (rv != CKR.CKR_OK)
                return rv;
            rv = Copy(session, encryptedData, data, ref dataLen);
            // A length query or CKR_BUFFER_TOO_SMALL leaves the operation active; anything else ends it (5.2).
            if (!(rv == CKR.CKR_BUFFER_TOO_SMALL || (rv == CKR.CKR_OK && data.IsNull)))
                EndOperationsLocked((ulong)session, CKF.CKF_DECRYPT);
            return rv;
        }
    }

    protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags)
    {
        lock (_lock)
        {
            _callLog.Add("C_SessionCancel");
            if (!SupportsSessionCancel)
                return CKR.CKR_FUNCTION_NOT_SUPPORTED;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            return EndOperationsLocked((ulong)session, (ulong)flags) ? CKR.CKR_OK : CKR.CKR_OPERATION_NOT_INITIALIZED;
        }
    }

    private CKR BeginOperation(NativeCULong session, NativeCULong key, ulong kind, string function)
    {
        lock (_lock)
        {
            _callLog.Add(function);
            CKR rv = InitOn(session, key);
            if (rv != CKR.CKR_OK)
                return rv;
            if (_operations.ContainsKey(((ulong)session, kind)))
                return CKR.CKR_OPERATION_ACTIVE;
            bool alwaysAuthenticate = _objects.TryGetValue((ulong)key, out Dictionary<CKA, byte[]>? attributes)
                && attributes.TryGetValue(CKA.CKA_ALWAYS_AUTHENTICATE, out byte[]? value) && value is [not 0, ..];
            _operations[((ulong)session, kind)] = new ActiveOperation(alwaysAuthenticate);
            return CKR.CKR_OK;
        }
    }

    // The operation a C_Sign or C_Decrypt continues: none is CKR_OPERATION_NOT_INITIALIZED, and one whose key needs a
    // context login that has not happened is CKR_USER_NOT_LOGGED_IN, which ends it (5.2).
    private CKR UseOperationLocked(ulong session, ulong kind)
    {
        if (!_operations.TryGetValue((session, kind), out ActiveOperation? operation))
            return CKR.CKR_OPERATION_NOT_INITIALIZED;
        if (operation.AlwaysAuthenticate && !operation.Authenticated)
        {
            _operations.Remove((session, kind));
            return CKR.CKR_USER_NOT_LOGGED_IN;
        }
        return CKR.CKR_OK;
    }

    // Ends the operations of the kinds in flags on session; whether there was any.
    private bool EndOperationsLocked(ulong session, ulong flags)
    {
        bool any = false;
        foreach (ulong kind in new[] { CKF.CKF_SIGN, CKF.CKF_DECRYPT }.Where(k => (flags & k) != 0))
            any |= _operations.Remove((session, kind));
        return any;
    }

    // PKCS#11 v3.2 C_Login with CKU_CONTEXT_SPECIFIC: only for an active operation whose key has
    // CKA_ALWAYS_AUTHENTICATE, else CKR_OPERATION_NOT_INITIALIZED with the operation untouched.
    private CKR ContextLoginLocked(ulong session, ReadOnlySpan<byte> pin)
    {
        ActiveOperation? operation = _operations
            .Where(o => o.Key.Session == session && o.Value.AlwaysAuthenticate)
            .Select(o => o.Value)
            .FirstOrDefault();
        if (operation is null)
            return CKR.CKR_OPERATION_NOT_INITIALIZED;
        _contextPins.Add(pin.ToArray());

        // An empty PIN is the protected authentication path: the device accepts it.
        if (!pin.IsEmpty && !pin.SequenceEqual(ExpectedPin))
        {
            if (++_wrongContextPins < LockAfter)
                return CKR.CKR_PIN_INCORRECT;
            // A locked PIN also logs the user out (private_key_objects.md), which ends this operation too.
            LogOutLocked();
            EndOperationsLocked(session, CKF.CKF_SIGN | CKF.CKF_DECRYPT);
            return CKR.CKR_PIN_LOCKED;
        }
        _wrongContextPins = 0;
        operation.Authenticated = true;
        return CKR.CKR_OK;
    }

    private CKR InitOn(NativeCULong session, NativeCULong key)
    {
        lock (_lock)
        {
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (_objects.ContainsKey((ulong)key) && !IsVisible((ulong)key))
                return CKR.CKR_KEY_HANDLE_INVALID;
            return CKR.CKR_OK;
        }
    }

    private CKR Copy(NativeCULong session, ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong outputLen)
    {
        lock (_lock)
        {
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (!output.IsNull)
            {
                if (output.Span.Length < input.Length)
                {
                    outputLen = (NativeCULong)(ulong)input.Length;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                input.CopyTo(output.Span);
            }
            outputLen = (NativeCULong)(ulong)input.Length;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
    {
        lock (_lock)
        {
            _initTokenCalls++;
            if ((ulong)slotId != SlotId)
                return CKR.CKR_SLOT_ID_INVALID;
            return _sessions.Count > 0 ? CKR.CKR_SESSION_EXISTS : CKR.CKR_OK;
        }
    }

    protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template)
    {
        DuringFind?.Invoke();
        Dictionary<CKA, byte[]> filter = ReadTemplate(template);
        lock (_lock)
        {
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            _finds[(ulong)session] = new Queue<ulong>(_objects
                .Where(o => IsVisible(o.Key) && filter.All(f => o.Value.TryGetValue(f.Key, out byte[]? v) && v.AsSpan().SequenceEqual(f.Value)))
                .Select(o => o.Key));
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
    {
        lock (_lock)
        {
            if (!_finds.TryGetValue((ulong)session, out Queue<ulong>? found))
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            int n = 0;
            while (n < objects.Length && found.Count > 0)
                objects[n++] = (NativeCULong)found.Dequeue();
            count = (NativeCULong)(ulong)n;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_FindObjectsFinal(NativeCULong session)
    {
        lock (_lock)
            return _finds.Remove((ulong)session) ? CKR.CKR_OK : CKR.CKR_OPERATION_NOT_INITIALIZED;
    }

    protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
    {
        DuringGetAttributeValue?.Invoke((ulong)objectHandle);
        lock (_lock)
        {
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (!IsVisible((ulong)objectHandle))
                return CKR.CKR_OBJECT_HANDLE_INVALID;

            Dictionary<CKA, byte[]> attributes = _objects[(ulong)objectHandle];
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                if (!attributes.TryGetValue((CKA)(ulong)template[i].type, out byte[]? value))
                {
                    template[i].valueLen = NativeCULong.MaxValue;
                    rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }
                if (template[i].value != IntPtr.Zero)
                {
                    if ((ulong)template[i].valueLen < (ulong)value.Length)
                    {
                        template[i].valueLen = NativeCULong.MaxValue;
                        rv = CKR.CKR_BUFFER_TOO_SMALL;
                        continue;
                    }
                    UnmanagedMemory.Write(template[i].value, value);
                }
                template[i].valueLen = (NativeCULong)(ulong)value.Length;
            }
            return rv;
        }
    }

    // A private object needs a login, as on a real token; CKA_PRIVATE defaults to false here.
    protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        => Create(session, template, defaultClass: null, ref objectId);

    /// <summary>The length of the ciphertext <c>C_EncapsulateKey</c> produces.</summary>
    public const int CiphertextLength = 16;

    /// <summary>
    /// Whether <c>C_EncapsulateKey</c> asked for the length only (a NULL buffer) creates the shared key anyway, and
    /// returns its handle, as SoftHSM does: the library's length probe then leaves a key behind.
    /// </summary>
    public bool EncapsulatesOnLengthProbe { get; set; }

    /// <summary>
    /// Every object made by <c>C_CreateObject</c> or a key-creating function (<c>C_GenerateKey</c>,
    /// <c>C_GenerateKeyPair</c>, <c>C_UnwrapKey</c>, <c>C_DeriveKey</c>, <c>C_EncapsulateKey</c>,
    /// <c>C_DecapsulateKey</c>), in order, whether or not it still exists.
    /// </summary>
    public IReadOnlyList<ulong> CreatedObjects
    {
        get { lock (_lock) return [.. _createdObjects]; }
    }

    private readonly List<ulong> _createdObjects = [];

    /// <summary>
    /// The handle the next object made will get, for a test that has the module give a destroyed object's number to
    /// a new one, as PKCS#11 allows.
    /// </summary>
    public ulong NextObjectHandle
    {
        get { lock (_lock) return _nextObject; }
        set { lock (_lock) _nextObject = value; }
    }

    // The key-creating functions accept any mechanism, key and input: each makes one object from its template, of
    // the class the function implies when the template names none, and a session object unless CKA_TOKEN is true.
    protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        => Create(session, template, CKO.CKO_SECRET_KEY, ref key);

    protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate,
        CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        lock (_lock)
        {
            CKR rv = Create(session, publicKeyTemplate, CKO.CKO_PUBLIC_KEY, ref publicKey);
            return rv == CKR.CKR_OK ? Create(session, privateKeyTemplate, CKO.CKO_PRIVATE_KEY, ref privateKey) : rv;
        }
    }

    protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
        CK_ATTRIBUTE[] template, ref NativeCULong key)
        => Create(session, template, CKO.CKO_SECRET_KEY, ref key);

    protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        => Create(session, template, CKO.CKO_SECRET_KEY, ref key);

    protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template,
        NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
    {
        if (ciphertext.IsNull)
        {
            ciphertextLen = (NativeCULong)(ulong)CiphertextLength;
            return EncapsulatesOnLengthProbe ? Create(session, template, CKO.CKO_SECRET_KEY, ref key) : CKR.CKR_OK;
        }
        if (ciphertext.Span.Length < CiphertextLength)
        {
            ciphertextLen = (NativeCULong)(ulong)CiphertextLength;
            return CKR.CKR_BUFFER_TOO_SMALL;
        }
        ciphertext.Span[..CiphertextLength].Fill(0xC7);
        ciphertextLen = (NativeCULong)(ulong)CiphertextLength;
        return Create(session, template, CKO.CKO_SECRET_KEY, ref key);
    }

    protected override CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template,
        ReadOnlySpan<byte> ciphertext, ref NativeCULong key)
        => Create(session, template, CKO.CKO_SECRET_KEY, ref key);

    // One object from template; CKA_CLASS defaults to defaultClass when given.
    private CKR Create(NativeCULong session, CK_ATTRIBUTE[] template, CKO? defaultClass, ref NativeCULong objectId)
    {
        Dictionary<CKA, byte[]> attributes = ReadTemplate(template);
        if (defaultClass is { } objectClass)
            attributes.TryAdd(CKA.CKA_CLASS, Ulong((ulong)objectClass));
        attributes.TryAdd(CKA.CKA_PRIVATE, [0]);
        attributes.TryAdd(CKA.CKA_LABEL, []);
        attributes.TryAdd(CKA.CKA_ID, []);
        attributes.TryAdd(CKA.CKA_TOKEN, [0]);
        lock (_lock)
        {
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (attributes[CKA.CKA_PRIVATE] is [not 0, ..] && _loggedIn is null)
                return CKR.CKR_USER_NOT_LOGGED_IN;
            ulong handle = _nextObject++;
            _objects[handle] = attributes;
            _createdObjects.Add(handle);
            if (attributes[CKA.CKA_TOKEN] is not [not 0, ..])
                _sessionObjects[handle] = (ulong)session;
            objectId = (NativeCULong)handle;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        lock (_lock)
        {
            _destroyObjectCalls.Add((ulong)objectId);
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (!IsVisible((ulong)objectId))
                return CKR.CKR_OBJECT_HANDLE_INVALID;
            _objects.Remove((ulong)objectId);
            _sessionObjects.Remove((ulong)objectId);
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
    {
        if (!signature.IsNull)
            DuringSign?.Invoke();
        lock (_lock)
        {
            _callLog.Add("C_Sign");
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            CKR rv = UseOperationLocked((ulong)session, CKF.CKF_SIGN);
            if (rv != CKR.CKR_OK)
                return rv;
            if (!signature.IsNull)
            {
                if (signature.Span.Length < SignatureLength)
                {
                    signatureLen = (NativeCULong)(ulong)SignatureLength;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                signature.Span[..SignatureLength].Fill(0x5A);
                EndOperationsLocked((ulong)session, CKF.CKF_SIGN);
            }
            signatureLen = (NativeCULong)(ulong)SignatureLength;
            return CKR.CKR_OK;
        }
    }

    protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        DuringGetSessionInfo?.Invoke(session);
        lock (_lock)
        {
            if (FailsNextLocked("C_GetSessionInfo", out CKR next))
                return next;
            if (_failing.TryGetValue((ulong)session, out CKR failure))
                return failure;
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
            return ContextLoginLocked((ulong)session, pin);
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

    private bool IsVisible(ulong objectHandle)
        => _objects.TryGetValue(objectHandle, out Dictionary<CKA, byte[]>? attributes)
            && (_loggedIn is not null || !IsPrivate(attributes));

    private static bool IsPrivate(Dictionary<CKA, byte[]> attributes)
        => attributes.TryGetValue(CKA.CKA_PRIVATE, out byte[]? value) && value is [not 0, ..];

    // C_Logout invalidates every handle to a private object for good, so each gets a new one.
    private void LogOutLocked()
    {
        if (_loggedIn is not null)
        {
            foreach (ulong handle in _objects.Where(o => IsPrivate(o.Value)).Select(o => o.Key).ToList())
            {
                Dictionary<CKA, byte[]> attributes = _objects[handle];
                _objects.Remove(handle);
                ulong renamed = _nextObject++;
                _objects[renamed] = attributes;
                if (_sessionObjects.Remove(handle, out ulong creator))
                    _sessionObjects[renamed] = creator;
            }
        }
        _loggedIn = null;
        _username = null;
    }

    private static Dictionary<CKA, byte[]> ReadTemplate(CK_ATTRIBUTE[] template)
    {
        var attributes = new Dictionary<CKA, byte[]>();
        foreach (CK_ATTRIBUTE attribute in template)
        {
            int length = (int)(ulong)attribute.valueLen;
            attributes[(CKA)(ulong)attribute.type] = attribute.value != IntPtr.Zero && length > 0
                ? UnmanagedMemory.Read(attribute.value, length)
                : [];
        }
        return attributes;
    }

    /// <summary>A <c>CK_ULONG</c> attribute value, in the platform's width.</summary>
    public static byte[] Ulong(ulong value)
    {
        var bytes = new byte[System.Runtime.CompilerServices.Unsafe.SizeOf<NativeCULong>()];
        System.Runtime.InteropServices.MemoryMarshal.Write(bytes, (NativeCULong)value);
        return bytes;
    }
}
