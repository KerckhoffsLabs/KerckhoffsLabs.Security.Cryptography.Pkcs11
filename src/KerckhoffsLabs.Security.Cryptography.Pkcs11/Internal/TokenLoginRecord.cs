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
internal sealed partial class TokenLoginRecord
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
    /// Runs on the thread that holds the transition semaphore, once it has run its hand-offs and before it releases the
    /// semaphore. A test seam, as <see cref="WhileHoldingTransition"/>: it lets a test post a hand-off in the window a
    /// release must still look at.
    /// </summary>
    internal Action? BeforeReleasingTransition { get; set; }

    /// <summary>
    /// Runs on a thread that found the transition semaphore taken and handed its action to the holder, before it looks
    /// at the semaphore again. A test seam, as <see cref="WhileHoldingTransition"/>: it lets a test have the holder
    /// release in between.
    /// </summary>
    internal Action? AfterPostingHandOff { get; set; }

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

    // The close of an ended login's anchor, deferred while another thread held its lock (EndLogin), or null.
    private Task? _anchorClosing;

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
