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
/// <see cref="WriteProtected"/> token; <c>CKR_SESSION_EXISTS</c> for <c>C_InitToken</c> while a session is
/// open; and the five <c>CKS_*</c> session states.
/// </para>
/// <para>
/// Objects (<see cref="AddObject"/>, <c>C_CreateObject</c>) answer <c>C_FindObjects*</c> and
/// <c>C_GetAttributeValue</c>. A private object (<c>CKA_PRIVATE</c> true) is visible only while the application
/// is logged in, and <c>C_Logout</c> invalidates its handle "even if a user is later logged back into the token":
/// it is given a new handle, so the old one answers <c>CKR_OBJECT_HANDLE_INVALID</c> for good.
/// </para>
/// <para>
/// <see cref="FailSession"/> makes every later call on one session fail with a given code, as a removed device
/// would, until the session is closed.
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
    private int _initTokenCalls;
    private readonly Dictionary<ulong, Dictionary<CKA, byte[]>> _objects = [];
    private readonly Dictionary<ulong, Queue<ulong>> _finds = [];
    private readonly Dictionary<ulong, CKR> _failing = [];
    private ulong _nextObject = 0x100;

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

    /// <summary>
    /// Runs at the start of every <c>C_FindObjectsInit</c>, before the token's lock: lets a test act while a search
    /// is in flight.
    /// </summary>
    public Action? DuringFind { get; set; }

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

    /// <summary>
    /// Makes every later call on <paramref name="session"/> answer <paramref name="rv"/> (say
    /// <c>CKR_DEVICE_REMOVED</c>), until the session is closed.
    /// </summary>
    public void FailSession(ulong session, CKR rv)
    {
        lock (_lock)
            _failing[session] = rv;
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
            _failing.Remove((ulong)session);
            _finds.Remove((ulong)session);

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

    protected override CKR C_Logout(NativeCULong session)
    {
        lock (_lock)
        {
            _logoutCalls++;
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
    protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitOn(session, key);

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

    protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitOn(session, key);

    protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
        => Copy(session, encryptedData, data, ref dataLen);

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
    {
        Dictionary<CKA, byte[]> attributes = ReadTemplate(template);
        attributes.TryAdd(CKA.CKA_PRIVATE, [0]);
        attributes.TryAdd(CKA.CKA_LABEL, []);
        attributes.TryAdd(CKA.CKA_ID, []);
        lock (_lock)
        {
            if (!IsOpen(session))
                return CKR.CKR_SESSION_HANDLE_INVALID;
            if (attributes[CKA.CKA_PRIVATE] is [not 0, ..] && _loggedIn is null)
                return CKR.CKR_USER_NOT_LOGGED_IN;
            ulong handle = _nextObject++;
            _objects[handle] = attributes;
            objectId = (NativeCULong)handle;
            return CKR.CKR_OK;
        }
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
                _objects[_nextObject++] = attributes;
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
