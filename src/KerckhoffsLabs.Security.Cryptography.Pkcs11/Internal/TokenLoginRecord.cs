using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The login state of one token for the whole process: who is logged in, the shares (<see cref="LoginHold"/>)
/// that keep the login, its generation, and the anchor session it was made on. One per slot of a module, kept
/// by the module's <see cref="TokenLoginRegistry"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The spec this follows</b> (PKCS#11 v3.2, session_mgmt_functions.md): a login is shared by all the
/// application's sessions with the token; a second <c>C_Login</c> answers <c>CKR_USER_ALREADY_LOGGED_IN</c>
/// for the same user and <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c> for another; closing the last session
/// logs out; <c>C_Logout</c> ends the login for every session and invalidates every private-object handle.
/// </para>
/// <para>
/// <b>Anchor session.</b> The record opens a session of its own before the first <c>C_Login</c>, sends
/// <c>C_Login</c>/<c>C_LoginUser</c>, <c>C_Logout</c> and an SO login's <c>C_InitPIN</c> on it, and closes it after the final
/// <c>C_Logout</c>. It keeps the login alive while no other session is open. It is
/// read/write for both users; a user's falls back to read-only when the token refuses read/write
/// (<c>CKR_TOKEN_WRITE_PROTECTED</c>) or has no read/write session left for the application
/// (<c>CKR_SESSION_COUNT</c>). The SO's never does: a read-only session would make the SO login fail.
/// </para>
/// <para>
/// <b>Lending.</b> On a token that allows the application no other session (<c>C_OpenSession</c> answers
/// <c>CKR_SESSION_COUNT</c>), the anchor is lent as the working session of a <see cref="Pkcs11Login.OpenSession()"/>
/// (<see cref="TryLend"/>), to one session at a time: a borrowing core (<see cref="Pkcs11SessionCore.Borrow"/>) works on
/// it, and the record's own sends take turns with it. A read/write anchor serves either access, a read-only one only
/// read-only sessions. The loan (<see cref="AnchorLoan"/>) ends when the borrower is disposed
/// (<see cref="Return"/>), when the library it came through is disposed (<see cref="ReleaseHoldersOf"/> reclaims it
/// before releasing that library's holds), or when the login ends, which closes the anchor and leaves the borrower
/// refusing every call. A borrower never closes the anchor. A lent anchor always has a hold, its borrower's, so the
/// final logout never meets one.
/// </para>
/// <para>
/// <b>Second logins.</b> A <see cref="Login"/> for the user already held is refused before the module
/// (<c>CKR_USER_ALREADY_LOGGED_IN</c>), its PIN never sent: PKCS#11 has no way to check a PIN against a login that is
/// already made, so a login that "shared" it would succeed with any PIN. A component that should use the login
/// takes a share explicitly, without a PIN: <see cref="Share"/> from a hold it was given, <see cref="TryShare"/>
/// for the login held on the slot (the normal user's only), or <see cref="ShareOrLogin(Pkcs11Library, TokenUser, string?, TokenInfo?, Func{SecurePin}?)"/>, which shares or logs in in
/// one step under the transition semaphore. Before refusing or sharing, the anchor is probed
/// (<c>C_GetSessionInfo</c>, never waiting for its lock): a lost anchor, or a state that no longer shows the user
/// logged in (the module dropped the login), ends the login, and the call logs in afresh. A login for anyone else
/// (another user type, or another username) is refused before the module.
/// </para>
/// <para>
/// <b>A login left on the token.</b> Only two things can leave the module logged in with no record of it: the anchor
/// lost on its own (<c>CKR_SESSION_HANDLE_INVALID</c>, <c>CKR_SESSION_CLOSED</c>) while other sessions of the
/// application stay open, and a <c>C_Logout</c> that failed or never reached the module. Its user is recorded, and it
/// is logged out as soon as no operation is in flight, on a session opened for that (login state is per application,
/// so any session ends it), once that session's state shows the same user logged in. Meanwhile private objects are
/// stamped as of a login that is never current, so none is used without a login. <c>CKR_PIN_LOCKED</c> from a context
/// login is taken the same way: some modules log the user out then, others (OpenSC, whose context PIN may be a
/// signature PIN of its own) keep the login, so it is recorded and settled by the same probe. A public state reported
/// leaves nothing behind. If that logout cannot be sent, the next first login that the module answers
/// <c>CKR_USER_ALREADY_LOGGED_IN</c> (or <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>) checks the new anchor's state for
/// the same user, logs it out, and logs in once more, so the PIN is checked. Any other login is refused
/// (<see cref="Pkcs11ForeignLoginException"/>). Login state is per application, so the library cannot tell its own login
/// left on the token from one another component of the process made meanwhile for the same user, through the same
/// module: the module's answer is the only evidence, and such a login is taken for the library's and logged out. A
/// login for another user than the one left behind, or with nothing left behind, is never adopted or logged out.
/// </para>
/// <para>
/// <b>Generations.</b> Each first login starts a generation; a share remembers the one it was taken in. When
/// the module reports the login gone (<see cref="MarkEnded"/>), a new generation starts at once: the old
/// shares become inactive, no longer count, and send no <c>C_Logout</c> when released. A new one also starts each
/// time a <c>C_Logout</c> has been sent (or given up), and each time a login left on the token is cleared: a private
/// object found while the module was still logged in, but with no login recorded (a logout in flight, a login being
/// rolled back), is stamped as of no login, and that stamp must not outlive the logout.
/// </para>
/// <para>
/// <b>Operations and the logout.</b> An operation that relies on the login is counted for its whole duration
/// (<see cref="EnterOperation"/>); entering one never waits. The final <c>C_Logout</c> waits for them instead: when
/// the last share goes while operations are in flight, the logout is left pending and sent by the thread whose
/// operation ends last. So a logout never lands inside an operation, as the spec asks ("before logging out, any
/// active operations should be finished"); releasing a share never blocks or throws, even from inside an
/// operation; and a login or a pinpad prompt never stalls operations. From the moment the logout is asked for, the
/// login is ending: no longer current, so private handles are refused, and operations that start then are not counted,
/// so the logout waits only for those already in flight. An object found or made inside an operation is stamped with
/// the login state when that operation began, so a login or logout that lands during its lookup makes the stamp
/// stale, never current. <see cref="WhenEnded"/> completes once the logout is sent (or given up).
/// </para>
/// <para>
/// <b>Operations and the first login.</b> PKCS#11 asks the same of <c>C_Login</c>. Every operation on the token's
/// sessions is tallied by the epoch it began in, counted on the gate or not; a first login that finds some in flight
/// starts a new epoch and waits for the earlier ones before it sends its PIN, outside the transition semaphore (an
/// operation's end may need it), and once: operations that start meanwhile neither wait nor are waited for, so the
/// wait is bounded by the operations already running. A login from inside an operation, on any token, skips it.
/// </para>
/// <para>
/// <b>Transitions.</b> A first login, a logout and the logout of a login left behind are serialized (a semaphore, waited
/// for outside every lock): a <c>C_Logout</c> in flight never lands after the next <c>C_Login</c>. The thread holding the
/// semaphore counts its own sends on no gate, and a logout that falls due on it (its probe the last operation to end)
/// is handed to it, to run before it releases the semaphore: it never waits for itself. A <see cref="Login"/> that
/// finds a logout pending or in flight waits for it, and logs in afresh once it is done; from inside an operation it
/// cannot wait (the pending logout waits for that operation) and throws. A login from the thread that holds the
/// semaphore (a <see cref="ShareOrLogin(Pkcs11Library, TokenUser, string?, TokenInfo?, Func{SecurePin}?)"/> PIN source that logs in to the same token) would wait for itself, and
/// throws too.
/// </para>
/// <para>
/// Lock order: a session's lock, then the anchor's lock, then this record's lock; never the reverse. No call into the
/// module is made under the record's lock. The transition semaphore stands apart: a thread may wait for it while
/// holding a session's lock (an operation's end sending a deferred logout), because its holder never waits for a lock
/// another thread holds. It only tries the anchor's lock (the probe), and otherwise works on sessions of its own (a new
/// anchor, the anchor it took out of the record, a session opened for a logout).
/// </para>
/// </remarks>
internal sealed class TokenLoginRecord
{
    private readonly NativeCULong _slotId;
    private readonly Lock _lock = new();

    // Serializes the transitions: a first login, a logout, and the logout of a login left on the token, so a C_Logout
    // in flight never lands after the next C_Login. Its holder's thread is _transitionOwner: that thread's own sends
    // count on no gate, and a logout it would otherwise wait for itself is handed to it (_handOffs); so is the logout of
    // a login left on the token, posted by another thread that found the semaphore taken (UnderTransitionOrPost).
    private readonly SemaphoreSlim _transition = new(1, 1);
    private int _transitionOwner;
    private readonly List<Action> _handOffs = [];

    // Set while no logout is pending or in flight: a Login that finds one waits on it.
    private readonly ManualResetEventSlim _noLogoutUnderway = new(initialState: true);

    // How many operations this thread is inside, on this record, and the login state when the outermost began: an
    // object found or made in an operation is stamped with the state the operation started under.
    private readonly ThreadLocal<int> _operationDepth = new();

    // How many operations this thread is inside, on any token: a first login from inside one does not wait for the
    // operations in flight, since a thread inside an operation on another token, logging in to this one's, would wait
    // for this thread as this thread waits for it.
    [ThreadStatic]
    private static int t_operationsOnThread;

    // The writes of the thread's depth: static, as the depth is the thread's, across all records.
    private static void EnterOperationOnThread() => t_operationsOnThread++;

    private static void ExitOperationOnThread() => t_operationsOnThread--;
    private readonly ThreadLocal<LoginStamp> _operationStamp = new();
    private readonly List<LoginHold> _holders = [];

    // All under _lock. Logged in exactly while _anchor is set; _loan only while _anchor is.
    private Pkcs11SessionCore? _anchor;
    private AnchorLoan? _loan;
    private TokenUser? _user;
    private string? _username;
    private long _generation;
    private ILogger _logger = NullLogger.Instance;
    private TaskCompletionSource _loginEnded = Completed();

    // Under _lock as well:
    // - the operations counted on the gate; the generation whose logout waits for them; whether a logout's C_Logout is
    //   being sent; whether the login is ending (its last holder gone: no longer current, new operations not counted);
    // - the user whose login this record ended without a C_Logout reaching the module, which the module may still hold
    //   (null when none); whether its logout waits for the operations in flight; and the library that made it, through
    //   which that logout opens a session.
    private int _activeOperations;
    private long? _pendingLogout;
    private bool _logoutInFlight;
    private bool _ending;
    private TokenUser? _leftBehind;
    private bool _leftBehindLogoutPending;
    private Pkcs11Library? _loginOwner;

    // Under _lock as well: every operation in flight on the token's sessions, counted or not, by the epoch it began in;
    // a first login made while some are in flight starts a new epoch and waits, outside the transition semaphore, for
    // those of the epochs before it (WaitForOperationsBefore), signalled through _operationsEnded.
    private int _operationEpoch;
    private readonly Dictionary<int, int> _operationsByEpoch = [];
    private TaskCompletionSource? _operationsEnded;

    // The module's registry, whose session tally refuses an SO login while a read-only session is open; null for a
    // record made on its own, which then leaves that to the module.
    private readonly TokenLoginRegistry? _registry;

    internal TokenLoginRecord(NativeCULong slotId, TokenLoginRegistry? registry = null)
    {
        _slotId = slotId;
        _registry = registry;
        RefusedPins = registry?.RefusedPinsFor(slotId) ?? new RefusedPins();
        // A record is new when the module's state is (its first load, or after C_Finalize): no login is held, so no
        // user's PIN is remembered for one.
        RefusedPins.ForgetUserPin();
    }

    /// <summary>The current login generation: changes on every first login and every reported end.</summary>
    public long Generation
    {
        get { lock (_lock) return _generation; }
    }

    /// <summary>Whether the application is logged in to the token through this record.</summary>
    public bool IsLoggedIn
    {
        get { lock (_lock) return _anchor is not null; }
    }

    /// <summary>Who is logged in, or <see langword="null"/> when no one is.</summary>
    public TokenUser? User
    {
        get { lock (_lock) return _user; }
    }

    /// <summary>
    /// The username of a <c>C_LoginUser</c> login, or <see langword="null"/> for a <c>C_Login</c> login or none.
    /// Kept to tell the same user from another, compared ordinally; never logged.
    /// </summary>
    public string? Username
    {
        get { lock (_lock) return _username; }
    }

    /// <summary>
    /// The PINs the token refused, never sent again for the same purpose: token logins here, the others by the slot and
    /// its sessions (see <see cref="Internal.RefusedPins"/>). Kept by the module's registry for the life of the process,
    /// so a record made after the module's <c>C_Finalize</c> finds the refusals of the one before.
    /// </summary>
    internal RefusedPins RefusedPins { get; }

    /// <summary>How many operations are counted on the token's gate (<see cref="EnterOperation"/>). A test seam.</summary>
    internal int ActiveOperations
    {
        get { lock (_lock) return _activeOperations; }
    }

    /// <summary>
    /// Whether the last share has gone and the logout waits for operations in flight. A test seam: it lets a test see
    /// the logout deferred, instead of guessing with time.
    /// </summary>
    internal bool IsLogoutPending
    {
        get { lock (_lock) return _pendingLogout is not null; }
    }

    /// <summary>
    /// Whether a login this record ended without a <c>C_Logout</c> reaching the module may still be held by it. A test
    /// seam.
    /// </summary>
    internal bool MayStillBeLoggedIn
    {
        get { lock (_lock) return _leftBehind is not null; }
    }

    /// <summary>The slot this record is for.</summary>
    internal NativeCULong SlotId => _slotId;

    /// <summary>
    /// The user of a login this record left on the token (ended without a <c>C_Logout</c> reaching the module), or
    /// <see langword="null"/>: carried to the module's next registry when this one is dropped with the module still
    /// initialized (<see cref="TokenLoginRegistry.Unloaded"/>).
    /// </summary>
    internal TokenUser? LeftBehindUser
    {
        get { lock (_lock) return _anchor is null ? _leftBehind : null; }
    }

    /// <summary>
    /// For a record just made: the module may still hold a login of <paramref name="user"/> that the module's previous
    /// registry left on the token. The next first login logs it out when the module answers it is held, as for a login
    /// this record left behind.
    /// </summary>
    internal void CarryLeftBehind(TokenUser user)
    {
        lock (_lock)
        {
            if (_anchor is null && _leftBehind is null)
                _leftBehind = user;
        }
    }

    /// <summary>
    /// Runs on the thread that holds the transition semaphore, right after it took it. A test seam: it lets a test act
    /// while a login or a logout holds the transition (release the last hold, say), instead of guessing with time.
    /// </summary>
    internal Action? WhileHoldingTransition { get; set; }

    /// <summary>
    /// Runs on a first login's thread when it is about to wait for the operations in flight on the token's sessions
    /// (outside the transition semaphore). A test seam, as <see cref="WhileHoldingTransition"/>.
    /// </summary>
    internal Action? WhileWaitingForOperations { get; set; }

    /// <summary>The operations in flight on the token's sessions, counted on the gate or not: for tests.</summary>
    internal int OperationsInFlight
    {
        get
        {
            lock (_lock)
            {
                int inFlight = 0;
                foreach (int count in _operationsByEpoch.Values)
                    inFlight += count;
                return inFlight;
            }
        }
    }

    /// <summary>The session the login was made on and is kept by, or <see langword="null"/> when not logged in.</summary>
    public Pkcs11SessionCore? Anchor
    {
        get { lock (_lock) return _anchor; }
    }

    /// <summary>The current loan of the anchor, or <see langword="null"/> when it is not lent.</summary>
    internal AnchorLoan? Loan
    {
        get { lock (_lock) return _loan; }
    }

    /// <summary>
    /// Whether <paramref name="generation"/> is the current login, and it is still logged in and not ending (its last
    /// holder gone, its logout pending): a private handle is usable only then.
    /// </summary>
    internal bool IsCurrent(long generation)
    {
        lock (_lock)
            return _anchor is not null && !_ending && _generation == generation;
    }

    /// <summary>
    /// The login state for a private object found or made now: see <see cref="LoginStamp"/>. Inside an operation, the
    /// state when the outermost operation on this thread began, so a login or logout that lands between that and the
    /// object's lookup makes the stamp stale rather than current. Outside one, the state now.
    /// </summary>
    internal LoginStamp CurrentStamp()
    {
        if (_operationDepth.Value > 0)
            return _operationStamp.Value;
        lock (_lock)
            return StampLocked();
    }

    // Under _lock. While a login this record ended may still be held by the module (_leftBehind), or its C_Logout is
    // taken but not yet sent (_logoutInFlight), private objects are visible though no login is current: they are
    // stamped as of a login, which is never current again, so an operation that starts in that window is refused its
    // private handles before C_*Init rather than having the C_Logout land inside it.
    private LoginStamp StampLocked()
        => new(_generation, LoggedIn: _anchor is not null || _leftBehind is not null || _logoutInFlight);

    /// <summary>
    /// Whether the login state <paramref name="stamp"/> recorded still holds, so a private object handle obtained
    /// under it is still valid: for a login, that same login is still current (<see cref="IsCurrent"/>); for no
    /// login, no login has started since.
    /// </summary>
    internal bool IsStillCurrent(LoginStamp stamp)
    {
        if (stamp.LoggedIn)
            return IsCurrent(stamp.Generation);
        lock (_lock)
            return _anchor is null && _leftBehind is null && !_logoutInFlight && _generation == stamp.Generation;
    }

    /// <summary>
    /// A task that completes when the login <paramref name="generation"/> names ends: logged out after its last holder
    /// went, or reported gone by the module. Completed already when that login is not the current one.
    /// </summary>
    internal Task WhenEnded(long generation)
    {
        // A logout in flight has taken the anchor out of the record, but its C_Logout is not sent yet: the login has
        // not ended. Its generation changes only once the C_Logout is sent (LogOutHeld).
        lock (_lock)
        {
            return (_anchor is not null || _logoutInFlight) && _generation == generation
                ? _loginEnded.Task
                : Task.CompletedTask;
        }
    }

    /// <summary>
    /// Logs <paramref name="user"/> in, and returns the caller's share of the login. Refuses a login while one is held
    /// (see the class remarks): the same user's with <c>CKR_USER_ALREADY_LOGGED_IN</c>, anyone else's with
    /// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>, both before the module and with no PIN sent.
    /// </summary>
    /// <param name="owner">The library the share comes through; its <c>Dispose</c> releases it.</param>
    /// <param name="user">Who logs in.</param>
    /// <param name="pin">The PIN, or <see langword="null"/> for the protected authentication path (a pinpad).</param>
    /// <param name="username">The username for <c>C_LoginUser</c>, or <see langword="null"/> for <c>C_Login</c>.</param>
    /// <param name="expectedToken">
    /// The token the caller selected the slot by, or <see langword="null"/>: checked against the slot's token after the
    /// login's session opens and before the PIN is sent, so a token swapped in meanwhile does not receive it.
    /// </param>
    /// <exception cref="Pkcs11AuthenticationException">
    /// A login is held through this record (<c>CKR_USER_ALREADY_LOGGED_IN</c> for the same user,
    /// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c> for another; refused before the module); or the module refused the
    /// login.
    /// </exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside this library.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// The token in the slot is not <paramref name="expectedToken"/> (<c>CKR_TOKEN_NOT_RECOGNIZED</c>); no PIN is sent.
    /// </exception>
    /// <exception cref="Pkcs11SessionException">
    /// An SO login while the library has a read-only session open on the slot (<c>CKR_SESSION_READ_ONLY_EXISTS</c>,
    /// refused before the module); or the anchor could not open because the token allows the application no more
    /// sessions (<c>CKR_SESSION_COUNT</c> from <c>C_OpenSession</c>, with a message giving the library's session tally
    /// on the slot). No <c>C_Login</c> is sent then.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Called from inside an operation on the token while the previous login's logout waits for operations to finish.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or the login.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is disposed, or its disposal began before the hold was taken.</exception>
    public LoginHold Login(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username,
        TokenInfo? expectedToken = null)
        => LoginCore(owner, user, username, expectedToken, shareHeld: false, () => pin);

    /// <summary>
    /// Shares the login held for <paramref name="user"/> (and <paramref name="username"/>), or logs in when none is
    /// held, deciding under the transition semaphore, so two callers never race into a refusal: for
    /// <see cref="Pkcs11Slot.ShareOrLogin(LoginCredential, string?)"/>. <paramref name="pinSource"/> runs when no login is held
    /// to share, outside the semaphore (it may take its time, or wait for a thread that logs in to the token); a login
    /// made meanwhile is then shared. The PIN it returns is disposed, sent or not. A share checks no PIN.
    /// </summary>
    /// <param name="owner">The library the share comes through.</param>
    /// <param name="user">Whose login to share or make.</param>
    /// <param name="username">The username for <c>C_LoginUser</c>, or <see langword="null"/>.</param>
    /// <param name="expectedToken">The token the slot was selected by, or <see langword="null"/> (see <see cref="Login"/>).</param>
    /// <param name="pinSource">The PIN's source, or <see langword="null"/> for the protected authentication path.</param>
    /// <exception cref="Pkcs11AuthenticationException">Another user is logged in, or the module refused the login.</exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside this library.</exception>
    public LoginHold ShareOrLogin(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        Func<SecurePin>? pinSource)
        => LoginCore(owner, user, username, expectedToken, shareHeld: true, () => pinSource is null ? null : TakePin(pinSource));

    /// <summary>
    /// As <see cref="ShareOrLogin(Pkcs11Library, TokenUser, string?, TokenInfo?, Func{SecurePin}?)"/>, with a PIN the
    /// caller keeps: never disposed here.
    /// </summary>
    public LoginHold ShareOrLogin(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        SecurePin pin)
        => LoginCore(owner, user, username, expectedToken, shareHeld: true, () => pin, disposeFetched: false);

    internal static SecurePin TakePin(Func<SecurePin> pinSource)
    {
        SecurePin pin = pinSource() ?? throw new InvalidOperationException("The PIN source returned null.");
        if (pin.IsDisposed)
        {
            throw new InvalidOperationException(
                "The PIN source returned a disposed SecurePin. The library disposes the PIN it is given once it is done " +
                "with it: return a new SecurePin from the source every time, never one you keep.");
        }
        return pin;
    }

    // The function a login calls: C_LoginUser for a named user, else C_Login. Refuses an empty username.
    private static string LoginMethodOf(string? username)
    {
        if (username is { Length: 0 })
            throw new ArgumentException("Username must not be empty.", nameof(username));
        return username is null ? OpLogin : OpLoginUser;
    }

    // The PIN a first login sends: a share's, fetched from its source outside the semaphore; a login's, its caller's.
    private static SecurePin? PinToSend(bool shareHeld, SecurePin? fetched, Func<SecurePin?> pin)
        => shareHeld ? fetched : pin();

    private LoginHold LoginCore(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        bool shareHeld, Func<SecurePin?> pin, bool disposeFetched = true)
    {
        ArgumentNullException.ThrowIfNull(owner);
        string method = LoginMethodOf(username);

        // Both made before anything changes: they run the caller's logger factory, and a throw then leaves nothing
        // half done.
        ILoggerFactory? loggerFactory = owner.LoggerFactory;
        ILogger logger = new CallOutFencedLogger((loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<TokenLoginRecord>());

        // The operations a first login waits for: those in flight when it first found it had to log in (null when none
        // was, or once they ended).
        int? operationsBefore = null;
        bool waitedForOperations = false;
        // A share's PIN comes from the caller's source, run outside the semaphore (it may take its time, or wait for a
        // thread that logs in to this token), once a first look found no login to share; owned, and disposed on the way
        // out, sent or not. A login's is the caller's, at hand.
        SecurePin? fetched = null;
        bool pinAtHand = !shareHeld;
        bool fetchPin = false;
        try
        {
            while (true)
            {
                // Before any wait: a logout handed to this thread would wait for it to release the semaphore.
                ThrowIfHoldingTransition();
                if (operationsBefore is { } epoch)
                {
                    WaitForOperationsBefore(epoch);
                    operationsBefore = null;
                    waitedForOperations = true;
                }
                if (fetchPin)
                {
                    fetchPin = false;
                    fetched = pin();
                    pinAtHand = true;
                }
                WaitForNoLogoutUnderway();
                WaitForAnchorClosed();
                AcquireTransition();
                try
                {
                    switch (HeldLogin(owner, user, username, method, shareHeld, expectedToken, out LoginHold? shared))
                    {
                        case Held.Shared:
                            return shared!;
                        case Held.LogoutUnderway:
                            continue;
                        default:
                            break;
                    }

                    // The share's PIN, fetched now the semaphore is let go: a login made meanwhile is then shared, and the
                    // PIN disposed unsent. Before the operations in flight are looked at, so a slow source (a prompt) is not
                    // followed by a login that lands inside operations started while it ran.
                    if (!pinAtHand)
                    {
                        // Not for a token swapped in since the slot was selected: the source (a prompt) is not run for it.
                        ThrowIfAnotherToken(owner, expectedToken, method);
                        fetchPin = true;
                        continue;
                    }

                    // PKCS#11 (C_Login): operations active when a login lands may or may not stay active, so they should
                    // finish first. Those in flight on the token's other sessions are waited for, once, outside the
                    // semaphore (an operation may need it on its way out); those that start meanwhile are not, so the wait
                    // ends. A login from inside an operation (on any token) does not wait: on this token its own operation
                    // is active, and on another, two such logins would wait for each other.
                    if (!waitedForOperations && t_operationsOnThread == 0 && StartOperationEpoch() is { } inFlight)
                    {
                        operationsBefore = inFlight;
                        continue;
                    }

                    return FirstLogin(owner, user, PinToSend(shareHeld, fetched, pin), username, loggerFactory, logger, expectedToken);
                }
                finally
                {
                    ReleaseTransition();
                }
            }
        }
        finally
        {
            if (shareHeld && disposeFetched)
                fetched?.Dispose();
        }
    }

    // The scope of a token login's PIN (RefusedPins): the token in the slot, the user, the username; and the token's
    // identity. A token that cannot be read is not sent the PIN: it could not be checked against the token's refusals,
    // nor a refusal remembered (Pkcs11Exception from C_GetTokenInfo).
    private PinScope LoginPinScope(Pkcs11Library owner, TokenUser user, string? username)
        => PinScopeOf(RefusedPins.TokenIdentity(new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory: null).GetTokenInfo()),
            user, username);

    // The scope of the PIN of user (and username) on the token identity names.
    internal PinScope PinScopeOf(string identity, TokenUser user, string? username)
    {
        RefusedPins.Purposes purpose = user == TokenUser.SecurityOfficer
            ? RefusedPins.Purposes.SecurityOfficer
            : RefusedPins.Purposes.User;
        byte[] name = username is null ? [] : System.Text.Encoding.UTF8.GetBytes(username);
        try
        {
            return new PinScope(purpose, identity, RefusedPins.Scope(purpose, identity, name));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(name);
        }
    }

    /// <summary>
    /// The scope of the PIN <c>C_SetPIN</c> changes on the token <paramref name="identity"/> names: the PIN of the user
    /// this record holds logged in (and its username), or the normal user's when none is (PKCS#11 C_SetPIN).
    /// </summary>
    internal PinScope SetPinScope(string identity)
    {
        TokenUser? user;
        string? username;
        lock (_lock)
        {
            user = _user;
            username = _username;
        }
        return PinScopeOf(identity, user ?? TokenUser.User, user is null ? null : username);
    }

    /// <summary>
    /// What a PIN is for (<see cref="RefusedPins"/>): its purpose and scope, on the token identity names.
    /// </summary>
    internal readonly record struct PinScope(RefusedPins.Purposes Purpose, string Identity, byte[] Scope);

    /// <summary>
    /// After <c>C_SetPIN</c> changed the user's PIN to <paramref name="pin"/>, under <see cref="RefusedPins.Serialized"/>:
    /// the PIN remembered for the user's login held, or being made, is the new one, or none when no user login is. Decided under the
    /// record's lock, so a logout that lands meanwhile cannot leave a PIN remembered with no login.
    /// </summary>
    internal void ReplaceUserPin(string identity, ReadOnlySpan<byte> pin)
    {
        lock (_lock)
        {
            // A first login being made remembered its PIN already, before the login is recorded: replaced too.
            bool remember = (_anchor is not null && _user == TokenUser.User) || RefusedPins.RemembersUserPin;
            RefusedPins.ForgetUserPin();
            if (remember)
                RefusedPins.RememberUserPin(identity, pin);
        }
    }

    private Pkcs11AuthenticationException RefusedBefore(string method, TokenUser user, string? username)
        => new(CKR.CKR_PIN_INCORRECT, method,
            $"{method}: the token in slot {(ulong)_slotId} refused this PIN before, for this " +
            $"{Describe(user, username)}, so it was not sent again: each wrong PIN costs one of the PIN's retries, " +
            "and repeating it would lock the PIN. Fix the PIN's source. If the token's PIN was changed outside this " +
            "library (to this PIN, or after it was put in the secret store), call Pkcs11Slot.ForgetRefusedPins().");

    private enum Held { None, Shared, LogoutUnderway }

    private Held NoneUnlessLogoutUnderway()
    {
        lock (_lock)
            return _pendingLogout is not null || _logoutInFlight ? Held.LogoutUnderway : Held.None;
    }

    // A login held by another user, or under another username, is refused: a token holds one login at a time.
    private void ThrowIfAnotherUser(TokenUser heldUser, string? heldUsername, TokenUser user, string? username, string method)
    {
        if (heldUser == user && string.Equals(heldUsername, username, StringComparison.Ordinal))
            return;

        // The usernames stay out of the message: it is commonly logged.
        throw new Pkcs11AuthenticationException(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, method,
            $"{method}: the token in slot {(ulong)_slotId} already has a {Describe(heldUser, heldUsername)} logged in " +
            "through this application, and a token holds one login at a time. Dispose every login and session that " +
            "holds it before logging in as someone else.");
    }

    // Under the transition semaphore. With a login held, once a probe of its anchor finds it still holding: refuses
    // another user (CKR_USER_ANOTHER_ALREADY_LOGGED_IN); for the same user, shares it (shareHeld, once the slot is found
    // to hold expectedToken still) or refuses (CKR_USER_ALREADY_LOGGED_IN). LogoutUnderway when a logout is pending or in
    // flight (the caller waits and looks again); None when no login is held, the probe included.
    private Held HeldLogin(Pkcs11Library owner, TokenUser user, string? username, string method, bool shareHeld,
        TokenInfo? expectedToken, out LoginHold? shared)
    {
        shared = null;
        Pkcs11SessionCore? anchor;
        TokenUser? heldUser;
        string? heldUsername;
        long generation;
        lock (_lock)
        {
            if (_pendingLogout is not null || _logoutInFlight)
                return Held.LogoutUnderway;
            anchor = _anchor;
            heldUser = _user;
            heldUsername = _username;
            generation = _generation;
        }

        if (anchor is null || heldUser is not { } held)
            return Held.None;

        // A lost anchor (a token pulled and put back, an HSM failover), or a module that dropped the login while the
        // anchor stayed open, ended the login: the probe reports it, the login ends, and this call logs in afresh, for
        // whichever user it asks for. Probed before the users are compared, so a login that is gone never refuses
        // another user's.
        if (!AnchorStillHolds(anchor, generation, held))
            return NoneUnlessLogoutUnderway();

        ThrowIfAnotherUser(held, heldUsername, user, username, method);

        if (shareHeld)
        {
            // A slot selected by its token shares a login only while it holds that token: a token swapped in since,
            // and logged in by another component, is not the one the caller asked for.
            ThrowIfAnotherToken(owner, expectedToken, method);
            lock (_lock)
            {
                if (_anchor is not null && _generation == generation && _holders.Count > 0 && !_ending)
                {
                    shared = AddHolderLocked(owner);
                    return Held.Shared;
                }
            }
            return NoneUnlessLogoutUnderway();
        }

        throw new Pkcs11AuthenticationException(CKR.CKR_USER_ALREADY_LOGGED_IN, method,
            $"{method}: the token in slot {(ulong)_slotId} already has this {Describe(user, username)} logged in through " +
            "this application, so the PIN was not sent: PKCS#11 cannot check a PIN against a login already made. Use " +
            "that login: Pkcs11Slot.ShareOrLogin, Pkcs11Login.Share() on a Pkcs11Login you were given, or " +
            "Pkcs11Slot.TryShareLogin for the login held on the slot; or dispose every login and session that holds it, " +
            "then log in again.");
    }

    // Whether the anchor of the login of generation still holds it: C_GetSessionInfo on it. A loss code ends the login
    // (Pkcs11SessionCore.ThrowIfError, then AnchorLost); a state other than the logged-in user's means the module
    // dropped the login, which ends it too (and leaves nothing on the token). A busy anchor (lent, in an operation) is
    // in use, so it holds. Any other failure is not evidence that the login ended.
    private bool AnchorStillHolds(Pkcs11SessionCore anchor, long generation, TokenUser user)
    {
        CKS? state;
        try
        {
            state = anchor.TrySendProbe();
        }
        catch (Exception ex) when (ex is Pkcs11Exception or ObjectDisposedException)
        {
            // A failure is no evidence, unless the anchor is known lost: then the login went with it, even if its loss
            // was seen before the login was recorded, when ending it was not this record's to do (AnchorLost).
            if (anchor.LostTo is var lost and not CKR.CKR_OK)
                EndLogin(lost, anchor);
            return IsCurrent(generation);
        }

        if (state is { } reported && TryUserOf(reported, out TokenUser? reportedUser) && reportedUser != user)
            EndLogin(CKR.CKR_USER_NOT_LOGGED_IN, anchor, moduleLoggedOut: true);
        return IsCurrent(generation);
    }

    // The user a session's state shows logged in, or null for a public session. False for a state PKCS#11 does not
    // define, which is no evidence either way: the caller acts as when the probe could not be answered.
    private static bool TryUserOf(CKS state, out TokenUser? user)
    {
        switch (state)
        {
            case CKS.CKS_RW_SO_FUNCTIONS:
                user = TokenUser.SecurityOfficer;
                return true;
            case CKS.CKS_RO_USER_FUNCTIONS or CKS.CKS_RW_USER_FUNCTIONS:
                user = TokenUser.User;
                return true;
            case CKS.CKS_RO_PUBLIC_SESSION or CKS.CKS_RW_PUBLIC_SESSION:
                user = null;
                return true;
            default:
                user = null;
                return false;
        }
    }

    // Under the transition semaphore, with no login held: opens the anchor, checks the token is the one selected, sends
    // the login on it, and records it.
    private LoginHold FirstLogin(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username,
        ILoggerFactory? loggerFactory, ILogger logger, TokenInfo? expectedToken)
    {
        string method = username is null ? OpLogin : OpLoginUser;
        ThrowIfReadOnlySessionBlocksSo(user, method);

        // Closed on every way out of this scope but one: the record keeps it once the login is recorded. Closing
        // the only session this record opened also leaves the token public again.
        using var anchor = new Owned<Pkcs11SessionCore>(OpenAnchor(owner, user, loggerFactory));
        ThrowIfAnotherToken(owner, expectedToken, method);

        // A PIN the token refused before for this login is not sent again, and one it refuses now is remembered
        // (RefusedPins), in one step with every other PIN sent to the slot. The token is read after the re-check above,
        // so a refusal is scoped to the token the PIN goes to. The pinpad has no PIN to remember: each one is typed
        // afresh.
        PinScope? scope = pin is null ? null : LoginPinScope(owner, user, username);
        if (scope is { } checkedScope)
        {
            Pkcs11SessionCore session = anchor.Value;
            TimeSpan? lifetime = owner.RefusedPinLifetime;
            // A PIN its caller keeps may be disposed meanwhile: zeroed only once checked, sent and recorded.
            using SecurePin.Use use = pin!.BeginUse();
            RefusedPins.Serialized(() => SendFirstLoginOnce(session, user, pin, username, method, checkedScope, lifetime));
        }
        else
        {
            // No PIN: the pinpad, which only a token with a protected authentication path has.
            anchor.Value.ThrowIfNoPinpadForRecord(method);
            SendFirstLogin(anchor.Value, user, pin, username, method);
        }

        // From here the module holds the login, and nothing else has seen it: any way out but recording it logs it back
        // out first. A login the module answered CKR_OK to but does not report, or a logger that threw on the way,
        // would otherwise stay on the token unrecorded, and the next login would take it for a foreign one.
        try
        {
            ThrowIfNotLoggedIn(anchor.Value, user, method);
        }
        catch
        {
            RefusedPins.ForgetUserPin();
            LogBackOut(anchor.Value, user, owner);
            throw;
        }

        lock (_lock)
        {
            // The owner's disposal began while the login was sent: its holds may already be released, so a
            // hold taken now would never be. Checked before the login is recorded, and undone below.
            if (!owner.IsDisposingOrDisposed)
            {
                _anchor = anchor.Release();
                _user = user;
                _username = username;
                _generation++;
                _logger = logger;
                _ending = false;
                _leftBehind = null;
                _loginOwner = owner;
                _loginEnded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                // Not checked again: a disposal that began since is to release this hold, and a throw here would leave
                // the login just recorded with no holder to log it out.
                return NewHolderLocked(owner);
            }
        }

        RefusedPins.ForgetUserPin();
        LogBackOut(anchor.Value, user, owner);
        throw OwnerDisposed();
    }

    // One step of RefusedPins, with every other PIN sent to the slot: a PIN refused before for this login is not sent
    // again, one the token refuses now is remembered, and one it takes is forgotten as refused and, for the user,
    // remembered as the user's.
    private void SendFirstLoginOnce(Pkcs11SessionCore session, TokenUser user, SecurePin pin, string? username,
        string method, PinScope checkedScope, TimeSpan? lifetime)
    {
        // The normal user's PIN is usually the context PIN too: one refused as a stale context PIN is not tried
        // as the user's either, so a stale secret costs one retry in all, not one per use.
        bool refused = RefusedPins.IsRefused(checkedScope.Scope, pin.Pin);
        bool refusedAsContext = user == TokenUser.User
            && RefusedPins.IsRefused(RefusedPins.ContextScope(checkedScope.Identity), pin.Pin);
        if (refused || refusedAsContext)
            throw RefusedBefore(method, user, username);
        try
        {
            SendFirstLogin(session, user, pin, username, method);
        }
        catch (Pkcs11Exception ex) when (RefusedPins.IsPinRefusal(ex.ReturnValue))
        {
            RefusedPins.Refuse(checkedScope.Purpose, checkedScope.Identity, checkedScope.Scope, pin.Pin, lifetime);
            throw;
        }
        // The PIN is the token's: a refusal of it for this login, kept from before it was changed outside the
        // library, is forgotten (the others stand); for the user, its refusal as a stale context PIN too (a key
        // with a PIN of its own keeps its refusal). In the same step as the send, so no other send sees it
        // half done.
        RefusedPins.ForgetPin(checkedScope.Scope, pin.Pin);
        if (user == TokenUser.User)
        {
            RefusedPins.ForgetPin(RefusedPins.ContextScope(checkedScope.Identity), pin.Pin);
            // The module holds the login from here: its PIN is remembered in the same step, so a context login
            // never sees the login made and its PIN not yet known (a key with a PIN of its own refusing the user's
            // correct PIN would be taken for a stale one). Forgotten on every way out below but recording it.
            RefusedPins.RememberUserPin(checkedScope.Identity, pin.Pin);
        }
    }

    // Still under the transition, with a login the module made and this record has not recorded, so nothing else saw
    // it: logs it back out on its anchor (other sessions of the application share it), which the caller then closes.
    // If that fails, the module may keep it, and it is recorded as left on the token, for the next first login.
    private void LogBackOut(Pkcs11SessionCore anchor, TokenUser user, Pkcs11Library owner)
    {
        bool loggedOut = false;
        try
        {
            anchor.SendLogout();
            loggedOut = true;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
        {
            loggedOut = true;
        }
        catch (Exception ex) when (!Log.IsFatal(ex))
        {
            // A module failure, or a logger that threw on the way: the caller's exception is what it is told.
        }
        finally
        {
            if (!loggedOut)
            {
                MarkLeftBehind(user, owner);
                // Logged out once more on a session opened for it, as the class remarks give, once this thread lets go
                // of the semaphore (a hand-off), rather than left for the next first login.
                UnderTransition(LogOutLeftBehind);
            }
            // Objects other sessions found while this login was on the token were stamped as of no login: that state
            // is over.
            lock (_lock)
                _generation++;
        }
    }

    // The module answered CKR_OK to the login: its state must now show the user logged in. A module that accepts a
    // login it does not make (NSS answers an empty PIN with CKR_OK on a token that needs no login, and stays public)
    // would leave a login recorded that the next probe finds gone, ending every hold of it; refused here instead.
    // A probe that cannot be answered is no evidence either way, but an anchor lost is (a failover between the login and
    // the probe): its loss ends nothing yet, as the login is not recorded, so it fails the login here, which the caller
    // logs back out, or records as left on the token.
    private void ThrowIfNotLoggedIn(Pkcs11SessionCore anchor, TokenUser user, string method)
    {
        CKS? state;
        try
        {
            state = anchor.TrySendProbe();
        }
        catch (Pkcs11Exception) when (anchor.LostTo == CKR.CKR_OK)
        {
            return;
        }
        if (state is not { } reported || !TryUserOf(reported, out TokenUser? reportedUser) || reportedUser == user)
            return;
        throw new Pkcs11AuthenticationException(CKR.CKR_USER_NOT_LOGGED_IN, method,
            $"{method}: the module accepted the login to the token in slot {(ulong)_slotId}, but its session still " +
            $"reports {reported}, not the {Describe(user, username: null)} logged in. The token may not need a login " +
            "(TokenInfo.Flags without LoginRequired): use it without one.");
    }

    // The token in the slot must still be the one the caller selected the slot by (a URI, a serial number, a label):
    // its identity is read again now that the login's session is open, and before any PIN is sent. A token reports its
    // own identity, so this catches a token swapped in meanwhile, not one made to look like the selected one.
    private void ThrowIfAnotherToken(Pkcs11Library owner, TokenInfo? expected, string method)
    {
        if (expected is null)
            return;
        TokenInfo now = new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory: null).GetTokenInfo();
        if (!IsSameToken(now, expected))
            throw AnotherToken((ulong)_slotId, method);
    }

    /// <summary>
    /// Whether <paramref name="now"/> reports the token <paramref name="expected"/> did: label, serial number,
    /// manufacturer and model, compared as the bytes the module reported (fields that are not UTF-8 can decode to the
    /// same text).
    /// </summary>
    internal static bool IsSameToken(TokenInfo now, TokenInfo expected)
        => string.Equals(now.RawLabel, expected.RawLabel, StringComparison.Ordinal)
            && string.Equals(now.RawSerialNumber, expected.RawSerialNumber, StringComparison.Ordinal)
            && string.Equals(now.RawManufacturerId, expected.RawManufacturerId, StringComparison.Ordinal)
            && string.Equals(now.RawModel, expected.RawModel, StringComparison.Ordinal);

    /// <summary>The refusal of a call made through a slot that no longer holds the token it was selected by.</summary>
    internal static Pkcs11TokenException AnotherToken(ulong slotId, string method)
        => new(CKR.CKR_TOKEN_NOT_RECOGNIZED, method,
            $"{method}: the token in slot {slotId} is no longer the one the slot was selected by (its label, serial " +
            "number, manufacturer or model changed): it was removed or swapped. No PIN was sent. Select the slot again.");

    // Sends the first login on anchor. The module answering that a user is logged in already means a login this record
    // left on the token (its user recorded in _leftBehind), which is logged out on the new anchor before the login is
    // sent once more, so the PIN is checked; or a login made outside this library, which is refused. The new anchor's
    // state tells which user the module holds: a login of another user than the one left behind is not this record's.
    private void SendFirstLogin(Pkcs11SessionCore anchor, TokenUser user, SecurePin? pin, string? username, string method)
    {
        CKR answer;
        try
        {
            Send(anchor, user, pin, username);
            return;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_USER_ALREADY_LOGGED_IN
            or CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
        {
            answer = ex.ReturnValue;
        }

        TokenUser? leftBehind;
        lock (_lock)
            leftBehind = _leftBehind;
        // The module's own answer to this login says which user it holds, and is the only evidence taken: the new
        // anchor's state is not, since some modules report an SO login as a user's on a session opened after it
        // (Kryoptic), which would make an SO login left behind look foreign, or a foreign SO login look like a user's
        // left behind, and have it logged out.
        bool ours = leftBehind is { } behind
            && ((answer == CKR.CKR_USER_ALREADY_LOGGED_IN && behind == user)
                || (answer == CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN && behind != user));
        if (!ours)
        {
            throw new Pkcs11ForeignLoginException(answer, method,
                $"{method}: the token in slot {(ulong)_slotId} is logged in already, but not through this library " +
                "(another component calling the module directly, or another PKCS#11 wrapper in this process). The " +
                "library does not take over a login it did not make: log that login out where it was made, then log " +
                "in again.");
        }

        // This record's own login, ended without a C_Logout reaching the module: its generation is over and its
        // handles refused already, so logging it out costs no holder anything.
        try
        {
            anchor.SendLogout();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
        {
            // Gone meanwhile (its last session closed): nothing to log out.
        }
        lock (_lock)
        {
            _leftBehind = null;
            _generation++;
        }
        Send(anchor, user, pin, username);
    }

    // The close of an ended login's anchor, deferred while another thread held its lock (EndLogin), or null.
    private Task? _anchorClosing;

    // Waits for an ended login's anchor to close, outside the semaphore: on a token that allows one session, the next
    // anchor would be refused while it is open. Not from inside an operation, which the close may be waiting for. The
    // close is deferred only while another thread holds the anchor's lock (a lent anchor's operation), so this waits for
    // that operation to end, as a first login waits for operations in flight anyway.
    private void WaitForAnchorClosed()
    {
        if (t_operationsOnThread == 0 && Volatile.Read(ref _anchorClosing) is { IsCompleted: false } closing)
            closing.Wait();
    }

    // Waits until no logout is pending or in flight; throws from inside an operation, which a pending logout may wait for.
    private void WaitForNoLogoutUnderway()
    {
        if (_noLogoutUnderway.IsSet)
            return;
        // Inside an operation on any token: on this one, the logout waits for that operation; on another, a logout pending
        // there may wait for an operation whose thread is waiting here, with no way out for either.
        if (t_operationsOnThread > 0)
        {
            throw new InvalidOperationException(
                "A login cannot be made from inside an operation (on this token or another) while the previous login's " +
                "logout waits for the operations in flight to finish: log in outside the operation.");
        }
        _noLogoutUnderway.Wait();
    }

    /// <summary>
    /// Takes a share of the login held on the token for <paramref name="user"/> (and <paramref name="username"/>):
    /// for <see cref="Pkcs11Slot.TryShareLogin(out Pkcs11Login?)"/>. Null when no such login is held, or it is on its way
    /// out (its last holder gone). Calls the module only to check the slot still holds <paramref name="expectedToken"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// The token in the slot is not <paramref name="expectedToken"/> (<c>CKR_TOKEN_NOT_RECOGNIZED</c>).
    /// </exception>
    internal LoginHold? TryShare(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        // The token is re-checked only when there is such a login to share: another user's makes this answer null, as
        // no login does, without calling the module.
        if (expectedToken is not null && Shareable(user, username))
            ThrowIfAnotherToken(owner, expectedToken, OpLogin);
        lock (_lock)
        {
            if (!ShareableLocked(user, username))
                return null;
            return AddHolderLocked(owner);
        }
    }

    private bool Shareable(TokenUser user, string? username)
    {
        lock (_lock)
            return ShareableLocked(user, username);
    }

    private bool ShareableLocked(TokenUser user, string? username)
        => _anchor is not null && _holders.Count != 0 && !_ending && _user == user
            && string.Equals(_username, username, StringComparison.Ordinal);

    /// <summary>
    /// Takes another share of the login <paramref name="existing"/> holds, without calling the module: for a
    /// session opened under a login, which keeps the login as long as it is open.
    /// </summary>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="existing"/> is released, or its login ended.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    public LoginHold Share(LoginHold existing, Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(owner);
        if (!ReferenceEquals(existing.Record, this))
            throw new ArgumentException("The hold belongs to another token's login.", nameof(existing));

        lock (_lock)
        {
            if (existing.IsReleased || _anchor is null || _ending || existing.Generation != _generation)
                throw LoginEnded();
            return AddHolderLocked(owner);
        }
    }

    /// <summary>
    /// Sends <c>C_InitPIN</c> on the anchor of the login <paramref name="hold"/> keeps, for
    /// <see cref="Pkcs11Login.InitUserPinWithPin"/> and <see cref="Pkcs11Login.InitUserPinWithPinpad"/>. The caller
    /// has checked the login is the Security Officer's, whose anchor is read/write: the "R/W SO Functions" state
    /// PKCS#11 v3.2 requires.
    /// </summary>
    /// <param name="hold">The caller's share of the login.</param>
    /// <param name="pin">The new normal-user PIN, or <see langword="null"/> for the protected authentication path.</param>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="hold"/> is released, or its login ended.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>; a lost anchor also ends the login.</exception>
    internal void InitUserPin(LoginHold hold, SecurePin? pin)
    {
        ArgumentNullException.ThrowIfNull(hold);

        // An operation: the login cannot be logged out under the send. The send waits for the anchor's lock.
        using IDisposable operation = EnterOperation();
        Pkcs11SessionCore anchor;
        lock (_lock)
        {
            if (hold.IsReleased || _anchor is null || hold.Generation != _generation)
                throw LoginEnded();
            anchor = _anchor;
        }

        try
        {
            anchor.SendInitPin(pin is null ? default : pin.Pin);
        }
        catch (ObjectDisposedException) when (!IsCurrent(hold.Generation))
        {
            // The module reported the login gone (MarkEnded) and the anchor was closed.
            throw LoginEnded();
        }
    }

    /// <summary>
    /// Lends the anchor of the login <paramref name="hold"/> keeps as the working session of a
    /// <see cref="Pkcs11Login.OpenSession()"/> whose <c>C_OpenSession</c> the module answered <c>CKR_SESSION_COUNT</c>:
    /// returns the borrowing core, or <see langword="null"/> with <paramref name="refusal"/> saying why it cannot be
    /// lent (it is lent already, or it is read-only and <paramref name="access"/> is read/write). Calls no module.
    /// </summary>
    /// <param name="hold">The share the new session will keep: it must be of the current login.</param>
    /// <param name="owner">The library the session comes through; its disposal reclaims the loan.</param>
    /// <param name="access">The access asked for: a read/write anchor serves either, a read-only one only <see cref="SessionAccess.ReadOnly"/>.</param>
    /// <param name="policy">The borrower's policy; <see langword="null"/> means <see cref="CryptoPolicy.Recommended"/>.</param>
    /// <param name="loggerFactory">The borrower's logger factory.</param>
    /// <param name="refusal">Why the anchor was not lent, for the <c>CKR_SESSION_COUNT</c> the caller throws.</param>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="hold"/> is released or its login ended.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    internal Pkcs11SessionCore? TryLend(LoginHold hold, Pkcs11Library owner, SessionAccess access, ICryptoPolicy? policy,
        ILoggerFactory? loggerFactory, out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(hold);
        ArgumentNullException.ThrowIfNull(owner);

        Pkcs11SessionCore anchor;
        long generation;
        lock (_lock)
        {
            refusal = LendRefusalLocked(hold, access);
            if (refusal is not null)
                return null;
            anchor = _anchor!;
            generation = _generation;
        }

        // Built outside the lock: it runs the caller's logger factory. Another thread may lend the anchor, or the
        // login end, meanwhile; checked again below before the loan is recorded.
        AnchorLoan loan;
        Pkcs11SessionCore borrower;
        try
        {
            loan = new AnchorLoan(anchor, owner, generation, anchor.SessionId);
            borrower = Pkcs11SessionCore.Borrow(anchor, loan, loggerFactory, policy);
        }
        catch (ObjectDisposedException) when (!IsCurrent(generation))
        {
            // The login ended meanwhile, which closed the anchor.
            throw LoginEnded();
        }
        loan.Borrower = borrower;
        BetweenLendPhases?.Invoke();

        ILogger logger;
        lock (_lock)
        {
            try
            {
                refusal = LendRefusalLocked(hold, access);
                if (refusal is null && (!ReferenceEquals(_anchor, anchor) || _generation != generation))
                    throw LoginEnded();
                // As AddHolderLocked: a loan recorded after the owner's disposal released its holds would never be reclaimed.
                if (owner.IsDisposingOrDisposed)
                    throw OwnerDisposed();
            }
            catch
            {
                loan.MarkEnded();
                throw;
            }

            if (refusal is not null)
            {
                // Never lent: nothing to return, and nothing else holds the borrower.
                loan.MarkEnded();
                return null;
            }
            _loan = loan;
            logger = _logger;
        }

        Log.AnchorLent(logger, (ulong)_slotId, loan.SessionHandle);
        return borrower;
    }

    /// <summary>
    /// Test seam: runs in <see cref="TryLend"/> on the lending thread after the borrower is built and before the loan
    /// is recorded, holding no lock, so a test can end the login, start the owner's disposal, or lend the anchor
    /// elsewhere in between. <see langword="null"/> outside tests.
    /// </summary>
    internal Action? BetweenLendPhases { get; set; }

    // Under _lock. Null when the anchor can be lent for access; else the refusal's message. A hold that is not of the
    // current login throws, as Share does.
    private string? LendRefusalLocked(LoginHold hold, SessionAccess access)
    {
        if (hold.IsReleased || _anchor is null || hold.Generation != _generation)
            throw LoginEnded();
        if (_loan is not null)
        {
            return $"{OpOpenSession}: the token in slot {(ulong)_slotId} allows this application no further " +
                "session of the kind asked for, so the login lends its own session as the working session, and it is " +
                "already lent to another session of the login. Dispose that session first: on this token a login has " +
                "one working session at a time.";
        }
        if (access == SessionAccess.ReadWrite && !_anchor.IsReadWrite)
        {
            return $"{OpOpenSession}: the token in slot {(ulong)_slotId} allows this application no more sessions of " +
                "that kind, and the login's own session, which it would lend, is read-only (the token refused a " +
                "read/write session when the login was made). Open a read-only session (SessionAccess.ReadOnly).";
        }
        return null;
    }

    /// <summary>
    /// Takes back the anchor lent under <paramref name="loan"/>, from the borrower's disposal; nothing when it is no
    /// longer the current loan (the login ended meanwhile, or it was already returned).
    /// </summary>
    internal void Return(AnchorLoan loan)
    {
        ArgumentNullException.ThrowIfNull(loan);
        ILogger logger;
        lock (_lock)
        {
            if (!ReferenceEquals(_loan, loan))
                return;
            _loan = null;
            logger = _logger;
        }
        Log.Quietly(() => Log.AnchorReturned(logger, (ulong)_slotId, loan.SessionHandle));
    }

    /// <summary>
    /// Releases every share that came through <paramref name="owner"/>, as its disposal does; the shares
    /// become inactive, and if no share of the current login is left, it is logged out. First takes back the anchor
    /// if it is lent to a session that came through <paramref name="owner"/> (the borrower's return runs, and it is
    /// disposed), so the final logout never meets a lent anchor.
    /// </summary>
    /// <remarks>From inside an operation, the logout is left pending until the operations in flight end.</remarks>
    public void ReleaseHoldersOf(Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(owner);

        AnchorLoan? reclaimed;
        lock (_lock)
        {
            reclaimed = _loan is { } loan && ReferenceEquals(loan.Owner, owner) ? loan : null;
            // Marked as it is chosen, under the lock Return takes: a borrower disposed by its user before this point
            // has already returned the loan and is not chosen, so its refusals never blame the library.
            reclaimed?.MarkReclaimed();
        }

        // Outside the record's lock: the return takes the gate and the anchor's lock, and destroys the session objects
        // made through the borrower. It waits for an operation in flight on it.
        reclaimed?.Borrower.Dispose();

        TakenAnchor? taken = null;
        ILogger logger;
        lock (_lock)
        {
            int released = 0;
            for (int i = _holders.Count - 1; i >= 0; i--)
            {
                LoginHold hold = _holders[i];
                if (!ReferenceEquals(hold.Owner, owner) || !hold.TryMarkReleased())
                    continue;
                _holders.RemoveAt(i);
                released++;
            }
            if (released > 0 && _holders.Count == 0 && _anchor is not null)
                taken = RequestLogoutLocked(_generation);
            // The login outlives the library that made it while another holds it: a login it leaves on the token is
            // logged out through one still alive.
            if (ReferenceEquals(_loginOwner, owner) && _holders.Count > 0)
                _loginOwner = _holders[0].Owner;
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
    }

    /// <summary>
    /// Records that the module reported the login gone (the anchor session lost, or <c>CKR_PIN_LOCKED</c> from
    /// a context-specific login): starts a new generation at once, so every existing share is inactive, no
    /// longer counts, and sends no <c>C_Logout</c>; and closes the anchor, so the next <see cref="Login"/>
    /// starts afresh.
    /// </summary>
    /// <param name="reason">The return code that reported it, for the log.</param>
    /// <remarks>Never waits, so an operation in flight may call this.</remarks>
    public void MarkEnded(CKR reason) => EndLogin(reason, onlyAnchor: null);

    // MarkEnded, or, with onlyAnchor, only while that session is the anchor (checked under the same hold of the
    // lock that ends the login). The anchor's own loss (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED,
    // CKR_DEVICE_REMOVED, CKR_TOKEN_NOT_PRESENT) can leave the module logged in, through the application's other
    // sessions: the last two can be transient on a network HSM, and do not say the module dropped anything. That login
    // is recorded (_leftBehind) and logged out as soon as no operation is in flight, on a session opened for it
    // (LogOutLeftBehind), which first reads the session state the module reports: a token really removed shows no
    // login, or opens no session, and the next first login, which then succeeds, clears the record. CKR_PIN_LOCKED from a
    // context login is recorded the same way: PKCS#11 has the user logged out then, but OpenSC keeps the login (its
    // context PIN may be a signature PIN of its own), and the probe tells which. After a public state reported
    // (moduleLoggedOut) or the module finalized (CKR_CRYPTOKI_NOT_INITIALIZED), the module holds nothing.
    private void EndLogin(CKR reason, Pkcs11SessionCore? onlyAnchor, bool moduleLoggedOut = false)
    {
        Pkcs11SessionCore? anchor;
        ILogger logger;
        TaskCompletionSource ended;
        bool logOutLeftBehind = false;
        lock (_lock)
        {
            if (onlyAnchor is not null && !ReferenceEquals(_anchor, onlyAnchor))
                return;
            _generation++;
            _holders.Clear();
            // Before the anchor closes: its borrower refuses every call from now on, and its return sends nothing.
            EndLoanLocked();
            anchor = _anchor;
            TokenUser? user = _user;
            _anchor = null;
            _user = null;
            _username = null;
            logger = _logger;
            ended = _loginEnded;
            _pendingLogout = null;
            _ending = false;
            RefusedPins.ForgetUserPin();
            if (anchor is not null)
            {
                if (!moduleLoggedOut && reason is CKR.CKR_SESSION_HANDLE_INVALID or CKR.CKR_SESSION_CLOSED
                        or CKR.CKR_DEVICE_REMOVED or CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_PIN_LOCKED)
                {
                    _leftBehind = user;
                    if (_activeOperations == 0)
                        logOutLeftBehind = true;
                    else
                        _leftBehindLogoutPending = true;
                }
                else
                {
                    _leftBehind = null;
                }
            }
            SignalIfNoLogoutLocked();
        }

        if (anchor is null)
            return;
        // Closed before the log: a logger that throws cannot leave the anchor open. Never waits for the anchor's lock:
        // this may run holding the transition semaphore (a probe that found the login gone), or inside an operation, and
        // the lock's holder (a borrower's operation, say) may be waiting for either; it then closes once the lock is free,
        // and the next first login waits for that (_anchorClosing), so it is not refused for the session still open.
        Volatile.Write(ref _anchorClosing, anchor.DisposeWithoutWaiting());
        ended.TrySetResult();
        if (logOutLeftBehind)
            UnderTransitionOrPost(LogOutLeftBehind);
        Log.TokenLoginEnded(logger, (ulong)_slotId, reason);
    }

    /// <summary>
    /// Ends the login when <paramref name="anchor"/>, the session it was made on, is reported lost (#363's codes),
    /// as <see cref="MarkEnded"/> does; nothing when <paramref name="anchor"/> is not this record's current anchor
    /// (a first login's anchor that failed before the login was recorded, or one already logged out).
    /// </summary>
    internal void AnchorLost(Pkcs11SessionCore anchor, CKR reason)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        EndLogin(reason, anchor);
    }

    /// <summary>
    /// Counts an operation that relies on the login until the returned lease is disposed: the final logout waits for
    /// it (see the class remarks). Never waits. Dispose it on the thread that took it, once.
    /// </summary>
    /// <remarks>
    /// Not counted: an operation on the thread that holds the transition semaphore (the record's own sends, which no
    /// logout can race, as a logout needs that semaphore), and one that starts while the login is ending (its last
    /// holder gone): such an operation finds private handles refused, so the logout need not wait for it.
    /// </remarks>
    public IDisposable EnterOperation()
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
            return NoOperation.Instance;

        bool counted;
        int epoch;
        LoginStamp stamp;
        lock (_lock)
        {
            counted = !_ending;
            if (counted)
                _activeOperations++;
            epoch = _operationEpoch;
            _operationsByEpoch[epoch] = _operationsByEpoch.GetValueOrDefault(epoch) + 1;
            stamp = StampLocked();
        }
        int depth = _operationDepth.Value;
        if (depth == 0)
            _operationStamp.Value = stamp;
        _operationDepth.Value = depth + 1;
        EnterOperationOnThread();
        return new OperationLease(this, counted, epoch, Environment.CurrentManagedThreadId);
    }

    // Under the transition semaphore, before a first login: with operations in flight on the token's sessions, starts a
    // new epoch and returns the one they began in or before, for the login to wait for; null when none is in flight.
    private int? StartOperationEpoch()
    {
        lock (_lock)
            return _operationsByEpoch.Count == 0 ? null : _operationEpoch++;
    }

    // Outside the transition semaphore: waits until every operation that began in epoch or an epoch before it has ended.
    // Bounded by those operations alone: one that starts later is in a later epoch.
    private void WaitForOperationsBefore(int epoch)
    {
        WhileWaitingForOperations?.Invoke();
        while (true)
        {
            Task ended;
            lock (_lock)
            {
                bool any = false;
                foreach (int began in _operationsByEpoch.Keys)
                    any |= began <= epoch;
                if (!any)
                    return;
                _operationsEnded ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                ended = _operationsEnded.Task;
            }
            ended.Wait();
        }
    }

    // The end of an operation: the last counted one to end sends a logout left pending, and the logout of a login left
    // on the token.
    private void ExitOperation(bool counted, int epoch)
    {
        _operationDepth.Value--;
        ExitOperationOnThread();

        TakenAnchor? taken = null;
        bool logOutLeftBehind = false;
        ILogger logger;
        lock (_lock)
        {
            // The last operation of its epoch: a first login waiting for it looks again.
            if (--_operationsByEpoch[epoch] == 0)
            {
                _operationsByEpoch.Remove(epoch);
                _operationsEnded?.TrySetResult();
                _operationsEnded = null;
            }
            if (!counted)
                return;

            _activeOperations--;
            if (_activeOperations == 0)
            {
                if (_pendingLogout is { } generation)
                {
                    _pendingLogout = null;
                    taken = TakeAnchorForLogoutLocked(generation);
                    SignalIfNoLogoutLocked();
                }
                logOutLeftBehind = _leftBehindLogoutPending;
                _leftBehindLogoutPending = false;
            }
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
        if (logOutLeftBehind)
            UnderTransitionOrPost(LogOutLeftBehind);
    }

    /// <summary>
    /// Releases one share, from <see cref="LoginHold.Dispose"/>; the last share of the current login logs out, at once,
    /// or once the operations in flight end. Never throws for being inside an operation.
    /// </summary>
    internal void Release(LoginHold hold)
    {
        TakenAnchor? taken = null;
        ILogger logger;
        lock (_lock)
        {
            if (_holders.Remove(hold) && _holders.Count == 0 && _anchor is not null && hold.Generation == _generation)
                taken = RequestLogoutLocked(hold.Generation);
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
    }

    // Under _lock, once the last share of the login of generation has gone: takes the anchor for the logout now, or,
    // with operations in flight, leaves the logout pending for the last of them (ExitOperation). The login is ending
    // from now on: not current, so no operation that starts now uses its private handles, and none of those counts.
    private TakenAnchor? RequestLogoutLocked(long generation)
    {
        if (_activeOperations == 0)
            return TakeAnchorForLogoutLocked(generation);
        _pendingLogout = generation;
        _ending = true;
        _noLogoutUnderway.Reset();
        return null;
    }

    // Under _lock. Lets a waiting Login go on once no logout is pending or in flight.
    private void SignalIfNoLogoutLocked()
    {
        if (_pendingLogout is null && !_logoutInFlight)
            _noLogoutUnderway.Set();
    }

    // Under _lock. Ends the loan of the anchor, if any, before the anchor closes.
    private void EndLoanLocked()
    {
        _loan?.MarkEnded();
        _loan = null;
    }

    // Under _lock. Refuses an owner whose disposal has begun: Pkcs11Library.Dispose marks itself disposing before it
    // releases its holds (ReleaseHoldersOf, which takes this lock), so either that release sees this hold, or this
    // check sees the mark.
    private LoginHold AddHolderLocked(Pkcs11Library owner)
    {
        if (owner.IsDisposingOrDisposed)
            throw OwnerDisposed();
        return NewHolderLocked(owner);
    }

    // Under _lock, once the caller found the owner not disposing under the same lock: the owner's disposal sets its flag
    // before it releases its holds under _lock (ReleaseHoldersOf), so a hold added under that lock is released by it.
    private LoginHold NewHolderLocked(Pkcs11Library owner)
    {
        var hold = new LoginHold(this, owner, _generation);
        _holders.Add(hold);
        if (_loginOwner is null || _loginOwner.IsDisposingOrDisposed)
            _loginOwner = owner;
        return hold;
    }

    // The anchor of a login taken out of the record for its logout, and who was logged in.
    private readonly record struct TakenAnchor(Pkcs11SessionCore Anchor, TokenUser User);

    // The final logout, of an anchor taken out of the record (TakeAnchorForLogoutLocked) with no operation in flight,
    // under the transition semaphore: so this C_Logout never lands after the next C_Login.
    // From inside an operation (on another token, or one not counted here), it is handed to the semaphore's holder rather
    // than waited for: releasing a share never blocks there (UnderTransitionOrPost). The logout is then underway until
    // that holder runs it, so a login from the same operation is refused (WaitForNoLogoutUnderway) rather than made.
    private void LogOut(TakenAnchor taken, ILogger logger)
    {
        if (t_operationsOnThread > 0)
            UnderTransitionOrPost(() => LogOutHeld(taken, logger));
        else
            UnderTransition(() => LogOutHeld(taken, logger));
    }

    // Under the transition semaphore. A C_Logout that fails, or never reaches the module (a logger that throws first),
    // leaves the module possibly logged in: recorded (_leftBehind), and logged out once more on a session opened for it
    // (LogOutLeftBehind) before the semaphore is released. The anchor is closed regardless, and closing it may itself
    // end the login (it can be the application's last session).
    private void LogOutHeld(TakenAnchor taken, ILogger logger)
    {
        bool loggedOut = false;
        CKR? failure = null;
        bool anchorClosed = false;
        try
        {
            using (taken.Anchor)
            {
                try
                {
                    taken.Anchor.SendLogout();
                    loggedOut = true;
                }
                catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
                {
                    loggedOut = true;
                }
                catch (Pkcs11Exception ex)
                {
                    failure = ex.ReturnValue;
                }
                catch (ObjectDisposedException)
                {
                    anchorClosed = true;
                }
                catch (Exception ex) when (!Log.IsFatal(ex))
                {
                    // Not the module's: a logger that threw on the way to C_Logout (the module's own failures are
                    // Pkcs11Exception). Dispose never throws, so this is a logout that did not reach the module: the
                    // login is left behind and logged out below.
                }
            }
        }
        finally
        {
            TaskCompletionSource ended;
            lock (_lock)
            {
                if (!loggedOut)
                    _leftBehind = taken.User;
                // Objects found while the C_Logout was on its way were stamped as of a login never current again; a
                // new generation also ends every stamp taken before it.
                _generation++;
                _logoutInFlight = false;
                _ending = false;
                SignalIfNoLogoutLocked();
                ended = _loginEnded;
            }
            ended.TrySetResult();
            if (!loggedOut)
                UnderTransition(LogOutLeftBehind);
        }

        if (failure is { } rv)
            Log.Quietly(() => Log.TokenLogoutFailed(logger, (ulong)_slotId, rv));
        if (anchorClosed)
            Log.Quietly(() => Log.TokenLogoutAnchorClosed(logger, (ulong)_slotId));
    }

    // A failed log-back-out of a login nothing saw (FirstLogin, its owner disposed): the module may keep it.
    private void MarkLeftBehind(TokenUser user, Pkcs11Library owner)
    {
        lock (_lock)
        {
            _leftBehind = user;
            _loginOwner ??= owner;
        }
    }

    // Under the transition semaphore. Logs out a login this record left on the token (_leftBehind), on a session opened
    // for it through the library that made the login: login state belongs to the application, so C_Logout on any of
    // its sessions ends it (PKCS#11 v3.2 C_Logout). That session's state tells first whether the module still holds
    // that user's login: a public state means nothing is left; another user's login is not this record's, and is left
    // alone. When no session can be opened, or the C_Logout fails, the login stays recorded, and the next first login
    // logs it out (SendFirstLogin).
    private void LogOutLeftBehind()
    {
        TokenUser leftBehind;
        Pkcs11Library? owner;
        lock (_lock)
        {
            if (_anchor is not null || _leftBehind is not { } user)
                return;
            // Decided when no operation was counted, and run maybe later (handed to the thread holding the semaphore):
            // with operations counted since, the last of them sends it instead. This narrows the window, it does not
            // close it: an operation may still start while the session below opens. Such an operation finds the
            // left-behind login's handles refused already, so a C_Logout inside it costs it nothing private.
            if (_activeOperations > 0)
            {
                _leftBehindLogoutPending = true;
                return;
            }
            leftBehind = user;
            owner = _loginOwner;
        }
        if (owner is null)
            return;

        // Through the library that made the login; once its disposal has begun, through the module-wide view the anchor
        // uses (a session outliving its load), so another load that keeps the module does not keep the login too. Once
        // that library is disposed in full (its view of the module gone), through another load still alive; with none,
        // the module is finalized or about to be, which ends the login.
        Pkcs11Library? via = owner.LowLevelLibrary is null ? _registry?.LiveLibrary() : owner;
        if (via is null)
            return;
        Pkcs11SessionCore session;
        try
        {
            session = new Pkcs11Slot(via, (ulong)_slotId, loggerFactory: null)
                .OpenSessionCore(readWrite: leftBehind == TokenUser.SecurityOfficer, anchor: via.IsDisposingOrDisposed);
        }
        catch (Pkcs11Exception)
        {
            return;
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        using (session)
        {
            if (!LoggedOutOn(session, leftBehind))
                return;
        }

        lock (_lock)
        {
            if (_anchor is null && _leftBehind is not null)
            {
                _leftBehind = null;
                // Objects found while it was on the token were stamped as of a login: that state is over.
                _generation++;
            }
        }
    }

    // Logs out the login of leftBehind left on the token, on session: whether it is gone now. Gone only on evidence: a
    // public state, or the C_Logout sent. A state that shows another user (a module may report an SO login as a user's
    // on a session opened after it, as Kryoptic does) or none at all leaves the login recorded, its handles refused, for
    // the next first login to settle.
    private static bool LoggedOutOn(Pkcs11SessionCore session, TokenUser leftBehind)
    {
        try
        {
            if (session.TrySendProbe() is not { } state || !TryUserOf(state, out TokenUser? moduleUser))
                return false;
            if (moduleUser is null)
                return true;
            if (moduleUser != leftBehind)
                return false;
            session.SendLogout();
            return true;
        }
        catch (Pkcs11Exception ex)
        {
            return ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN;
        }
        catch (Exception ex) when (!Log.IsFatal(ex))
        {
            // A logger that threw on the way (the module's failures are Pkcs11Exception): the login stays recorded, for
            // the next first login to settle; this runs on disposal paths, which never throw.
            return false;
        }
    }

    // Under _lock, with no operation counted. Takes the anchor out of the record, for LogOut to close, if the login
    // of generation is still current and unheld; else null, and the record is left as it was. From here on the login
    // is not current, so an operation that starts now finds its private handles refused.
    private TakenAnchor? TakeAnchorForLogoutLocked(long generation)
    {
        if (_holders.Count != 0 || _anchor is null || _user is not { } user || _generation != generation)
            return null;
        // Not expected: a lent anchor has its borrower's hold. Should one be left, it is not lent any longer.
        EndLoanLocked();
        Pkcs11SessionCore anchor = _anchor;
        _anchor = null;
        _user = null;
        _username = null;
        _ending = false;
        RefusedPins.ForgetUserPin();
        _logoutInFlight = true;
        _noLogoutUnderway.Reset();
        return new TakenAnchor(anchor, user);
    }

    // Takes the transition semaphore, waiting its turn, and records this thread as its holder.
    private void AcquireTransition()
    {
        ThrowIfHoldingTransition();
        _transition.Wait();
        TookTransition();
    }

    // Records this thread as the holder of the semaphore it just took.
    private void TookTransition()
    {
        Volatile.Write(ref _transitionOwner, Environment.CurrentManagedThreadId);
        WhileHoldingTransition?.Invoke();
    }

    // The semaphore is not reentrant: a thread that holds it (a logger the library calls while logging in, logging in
    // to the same token) would wait for itself forever.
    private void ThrowIfHoldingTransition()
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
        {
            throw new InvalidOperationException(
                "A login to this token is already being made on this thread (code the library called while logging in, " +
                "such as a logger): it cannot log in, share or log out on the same token until that login is done.");
        }
    }

    // Runs what was handed to this thread while it held the semaphore, or posted to its holder (UnderTransitionOrPost),
    // then releases it. An action posted after the hand-offs ran, by a thread that then found the semaphore still
    // taken, is run here too: the semaphore is taken back, if free, until none is left.
    private void ReleaseTransition()
    {
        while (true)
        {
            try
            {
                RunHandOffs();
            }
            finally
            {
                Volatile.Write(ref _transitionOwner, 0);
                _transition.Release();
            }
            lock (_lock)
            {
                if (_handOffs.Count == 0)
                    return;
            }
            // Free: this thread runs them. Taken: its new holder runs them as it releases it.
            if (!_transition.Wait(0))
                return;
            TookTransition();
        }
    }

    // Runs every hand-off, each even if the one before it threw. A throw is logged and dropped: hand-offs are logouts
    // and their follow-ups, run on paths that never throw (a release, an operation's end), and the caller's own outcome
    // (a login just made, whose hold would leak) must not be replaced by one.
    private void RunHandOffs()
    {
        while (true)
        {
            Action next;
            ILogger logger;
            lock (_lock)
            {
                if (_handOffs.Count == 0)
                    return;
                next = _handOffs[0];
                _handOffs.RemoveAt(0);
                logger = _logger;
            }
            try
            {
                next();
            }
            catch (Exception ex) when (!Log.IsFatal(ex))
            {
                Log.Quietly(() => Log.TokenHandOffFailed(logger, (ulong)_slotId, ex));
            }
        }
    }

    // Runs action under the transition semaphore. On the thread that holds it already (a logout due as the record's
    // own send ends, a login's probe finding its anchor lost), the semaphore cannot be taken again: the action is
    // handed to this thread, to run before it releases the semaphore.
    internal void UnderTransition(Action action)
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
        {
            lock (_lock)
                _handOffs.Add(action);
            return;
        }
        AcquireTransition();
        try
        {
            action();
        }
        finally
        {
            ReleaseTransition();
        }
    }

    // Runs action under the transition semaphore if it is free, or hands it to the thread holding it, which runs it as
    // it releases the semaphore (ReleaseTransition): never waits. For the logout of a login left on the token, sent from
    // the end of an operation, while that operation's session lock is held: waiting there for a first login that holds
    // the semaphore across a pinpad prompt would stall the session. A first login logs out such a login itself
    // (SendFirstLogin), so nothing waits for this one. And for the final logout from inside an operation (LogOut).
    private void UnderTransitionOrPost(Action action)
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId || !_transition.Wait(0))
        {
            lock (_lock)
                _handOffs.Add(action);
            // The holder may have run its hand-offs and released since: take the semaphore now, if free, to run them.
            if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId || !_transition.Wait(0))
                return;
            TookTransition();
            ReleaseTransition();
            return;
        }
        TookTransition();
        try
        {
            action();
        }
        finally
        {
            ReleaseTransition();
        }
    }

    // PKCS#11 v3.2 C_Login: an SO login fails with CKR_SESSION_READ_ONLY_EXISTS while the application has a
    // read-only session open. Refused here from the sessions the library has open through any load of the module
    // (the record knows them); sessions opened outside the library are left to the module's answer.
    private void ThrowIfReadOnlySessionBlocksSo(TokenUser user, string method)
    {
        if (user != TokenUser.SecurityOfficer || _registry is null)
            return;
        int readOnly = _registry.Sessions(_slotId).ReadOnly;
        if (readOnly == 0)
            return;
        throw Pkcs11Exception.Create(CKR.CKR_SESSION_READ_ONLY_EXISTS, method,
            $"{method}: the Security Officer cannot log in to the token in slot {(ulong)_slotId} while this " +
            $"application has a read-only session open on it ({readOnly} open), as PKCS#11 forbids. Close the " +
            "read-only sessions first, or open read/write ones.");
    }

    // Opens the anchor read/write, so that it can do what any session of the login does should the token allow no
    // other. A user anchor falls back to read-only where the token refuses read/write (write-protected) or has no
    // read/write session left for this application; an SO anchor does not, as the SO has only read/write sessions
    // (PKCS#11 v3.2 C_OpenSession, CKR_SESSION_READ_WRITE_SO_EXISTS). CKR_SESSION_COUNT from the last attempt keeps
    // its code, with a message that says what holds the token's sessions.
    private Pkcs11SessionCore OpenAnchor(Pkcs11Library owner, TokenUser user, ILoggerFactory? loggerFactory)
    {
        // Throws ObjectDisposedException for a disposed owner. The anchor survives that owner's disposal
        // (it is shared by every load of the module), so it calls through a view that outlives the load.
        var slot = new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory);
        try
        {
            try
            {
                return slot.OpenSessionCore(readWrite: true, anchor: true);
            }
            catch (Pkcs11Exception ex) when (user == TokenUser.User
                && ex.ReturnValue is CKR.CKR_TOKEN_WRITE_PROTECTED or CKR.CKR_SESSION_COUNT)
            {
                return slot.OpenSessionCore(readWrite: false, anchor: true);
            }
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_SESSION_COUNT)
        {
            throw NoSessionForLogin(ex);
        }
    }

    // The anchor could not open because the token allows this application
    // no more sessions. From the library's tally on the slot, which never counts sessions opened outside it.
    private Pkcs11SessionException NoSessionForLogin(Pkcs11Exception moduleAnswer)
    {
        int? open = _registry?.Sessions(_slotId) is { } tally ? tally.ReadOnly + tally.ReadWrite : null;
        string held = open switch
        {
            > 0 => $"it has {open} session(s) open on the slot through this library: dispose them, or log in first " +
                "and open sessions through the login (Pkcs11Login.OpenSession).",
            0 => "the sessions that use it up were not opened through this library: close them, or log in first and " +
                "open sessions through the login (Pkcs11Login.OpenSession).",
            _ => "close the sessions this application has open on it, or log in first and open sessions through the " +
                "login (Pkcs11Login.OpenSession).",
        };
        return new Pkcs11SessionException(CKR.CKR_SESSION_COUNT, OpOpenSession,
            $"{OpOpenSession}: a login needs a session of its own, and the token in slot {(ulong)_slotId} allows this " +
            $"application no further session of the kind asked for (read/write, or any); {held}", moduleAnswer);
    }

    private static void Send(Pkcs11SessionCore anchor, TokenUser user, SecurePin? pin, string? username)
    {
        CKU userType = user == TokenUser.SecurityOfficer ? CKU.CKU_SO : CKU.CKU_USER;
        ReadOnlySpan<byte> secret = pin is null ? default : pin.Pin;
        if (username is null)
            anchor.SendLogin(userType, secret);
        else
            anchor.SendLoginUser(userType, secret, username);
    }

    private static ObjectDisposedException OwnerDisposed()
        => new(nameof(Pkcs11Library), "The library this login was made through is disposed, or being disposed.");

    private static Pkcs11LoginEndedException LoginEnded()
        => new(OpLogin, "This login has ended: it was disposed, logged out (or its logout is pending, its last holder gone), " +
            "or the module reported it gone. Log in again.");

    private static TaskCompletionSource Completed()
    {
        var done = new TaskCompletionSource();
        done.SetResult();
        return done;
    }

    private static string Describe(TokenUser user, string? username)
        => (user == TokenUser.SecurityOfficer ? "Security Officer" : "normal user") + (username is null ? "" : " (named)");

    /// <summary>The count an operation takes on the record; given back once, on the thread that took it.</summary>
    private sealed class OperationLease(TokenLoginRecord record, bool counted, int epoch, int thread) : IDisposable
    {
        private int _released;

        // A lease given back on another thread would unbalance the per-thread operation depth and stamp the next
        // operation with a stale login: that is a bug in the library, refused loudly rather than absorbed.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3877:Exceptions should not be thrown from unexpected methods",
            Justification = "Disposal on a foreign thread is an internal invariant violation, never caller-reachable.")]
        public void Dispose()
        {
            if (Environment.CurrentManagedThreadId != thread)
            {
                throw new InvalidOperationException(
                    "An operation's count on the token's gate must be given back on the thread that took it.");
            }
            if (Interlocked.Exchange(ref _released, 1) == 0)
                record.ExitOperation(counted, epoch);
        }
    }

    /// <summary>The lease of an operation that counts on no gate (see <see cref="EnterOperation"/>).</summary>
    private sealed class NoOperation : IDisposable
    {
        public static readonly NoOperation Instance = new();

        public void Dispose()
        {
            // Nothing was counted.
        }
    }
}

/// <summary>
/// The login state of a token when a private object handle was obtained: the record's generation, and whether a
/// login was held then. The handle is valid only while that state lasts (PKCS#11 v3.2 <c>C_Logout</c>: handles to
/// private objects become invalid, even if a user logs back in).
/// </summary>
/// <remarks>
/// Taken from the token's login record, never from the session that found the object: a session that holds no
/// login still sees the application's login (login state is per application and token), so a private object it
/// finds is tied to that login like any other. A private object found while not logged in (a module that shows
/// private objects to public sessions) is tied to that state: any later login ends it.
/// </remarks>
/// <param name="Generation">The record's <see cref="TokenLoginRecord.Generation"/>.</param>
/// <param name="LoggedIn">Whether a login was held.</param>
internal readonly record struct LoginStamp(long Generation, bool LoggedIn);
