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
/// <c>CKR_SESSION_COUNT</c>), the anchor is lent as the working session of a <see cref="Pkcs11Login.OpenSession"/>
/// (<see cref="TryLend"/>), to one session at a time: a borrowing core (<see cref="Pkcs11SessionCore.Borrow"/>) works on
/// it, and the record's own sends take turns with it. A read/write anchor serves either access, a read-only one only
/// read-only sessions. The loan (<see cref="AnchorLoan"/>) ends when the borrower is disposed
/// (<see cref="Return"/>), when the library it came through is disposed (<see cref="ReleaseHoldersOf"/> reclaims it
/// before releasing that library's holds), or when the login ends, which closes the anchor and leaves the borrower
/// refusing every call. A borrower never closes the anchor. A lent anchor always has a hold, its borrower's, so the
/// final logout never meets one.
/// </para>
/// <para>
/// <b>Shares.</b> A <see cref="Login"/> for the user already held still sends the PIN, and accepts
/// <c>CKR_USER_ALREADY_LOGGED_IN</c> only because this record knows the application holds that user. A token
/// need not check the PIN then, so such a login is a share of the existing login, not a second
/// authentication. A login for anyone else (another user type, or another username) is refused before the
/// module. When the last share of the current login goes, <c>C_Logout</c> is sent and the anchor closed.
/// </para>
/// <para>
/// <b>Generations.</b> Each first login starts a generation; a share remembers the one it was taken in. When
/// the module reports the login gone (<see cref="MarkEnded"/>), a new generation starts at once: the old
/// shares become inactive, no longer count, and send no <c>C_Logout</c> when released.
/// </para>
/// <para>
/// <b>Gate.</b> A slot-wide reader/writer lock orders logins and logouts against operations: an operation that
/// relies on the login holds it shared (<see cref="EnterOperation"/>) for its whole duration; the first
/// <c>C_Login</c> and the final <c>C_Logout</c> hold it exclusive. A login that shares the login already held
/// holds it shared, like an operation. So a logout never lands inside an operation, as the spec asks ("before
/// logging out, any active operations should be finished"); a slow pinpad on a first login or a final logout
/// delays operations on the slot, a slow pinpad on a share delays other logins, and also every new operation once a
/// first login or final logout is waiting behind it (the gate makes new shared holders wait for a waiting exclusive
/// one). The gate is recursive, so
/// a thread that holds it exclusive (sending a login on the anchor) can enter an operation; a thread inside an
/// operation cannot release a share (<see cref="ThrowIfInsideOperation"/>), since the last one needs it
/// exclusive.
/// </para>
/// <para>
/// Lock order: an ordinary session's lock, then the gate, then the send lock (the turns the sends on the anchor
/// take), then the anchor's lock, then this record's lock; never the reverse. The anchor's own core takes the gate
/// before its lock (<see cref="Pkcs11SessionCore.IsAnchorSide"/>), since this record closes the anchor while holding
/// the gate. The sends on the anchor (<see cref="Pkcs11SessionCore.AcquireForRecord"/>) wait for its lock rather than
/// refuse a thread that holds it, and the send lock is never held with the record's lock. No call into the module
/// is made under the record's lock.
/// </para>
/// </remarks>
internal sealed class TokenLoginRecord
{
    private readonly NativeCULong _slotId;
    private readonly ReaderWriterLockSlim _gate = new(LockRecursionPolicy.SupportsRecursion);
    private readonly Lock _lock = new();

    // Takes turns for the logins sent on the anchor, which shares send concurrently under the shared gate.
    private readonly Lock _sendLock = new();
    private readonly List<LoginHold> _holders = [];

    // All under _lock. Logged in exactly while _anchor is set; _loan only while _anchor is.
    private Pkcs11SessionCore? _anchor;
    private AnchorLoan? _loan;
    private TokenUser? _user;
    private string? _username;
    private long _generation;
    private ILogger _logger = NullLogger.Instance;

    // The module's registry, whose session tally refuses an SO login while a read-only session is open; null for a
    // record made on its own, which then leaves that to the module.
    private readonly TokenLoginRegistry? _registry;

    internal TokenLoginRecord(NativeCULong slotId, TokenLoginRegistry? registry = null)
    {
        _slotId = slotId;
        _registry = registry;
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
    /// How many threads are waiting to hold the gate exclusive (a first login or a final logout waiting for operations
    /// in flight). A test seam: it lets a test wait until such a thread is blocked, instead of guessing with time.
    /// </summary>
    internal int WaitingForExclusiveGate => _gate.WaitingWriteCount;

    /// <summary>
    /// How many threads are waiting to hold the gate shared (an operation, or a share's login, queued behind a waiting
    /// first login or final logout). A test seam, like <see cref="WaitingForExclusiveGate"/>.
    /// </summary>
    internal int WaitingForSharedGate => _gate.WaitingReadCount;

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

    /// <summary>Whether <paramref name="generation"/> is the current login, and it is still logged in.</summary>
    internal bool IsCurrent(long generation)
    {
        lock (_lock)
            return _anchor is not null && _generation == generation;
    }

    /// <summary>
    /// The login state now, for a private object found or made under it: see <see cref="LoginStamp"/>. Taken while
    /// the gate is held (inside an operation), so it is the state the object's lookup or creation ran under.
    /// </summary>
    internal LoginStamp CurrentStamp()
    {
        lock (_lock)
            return new LoginStamp(_generation, LoggedIn: _anchor is not null);
    }

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
            return _anchor is null && _generation == stamp.Generation;
    }

    /// <summary>
    /// Logs <paramref name="user"/> in, or shares the login already held for the same user, and returns the
    /// caller's share of it.
    /// </summary>
    /// <param name="owner">The library the share comes through; its <c>Dispose</c> releases it.</param>
    /// <param name="user">Who logs in.</param>
    /// <param name="pin">The PIN, or <see langword="null"/> for the protected authentication path (a pinpad).</param>
    /// <param name="username">The username for <c>C_LoginUser</c>, or <see langword="null"/> for <c>C_Login</c>.</param>
    /// <exception cref="Pkcs11AuthenticationException">
    /// Someone else is logged in through this record (<c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>, refused before
    /// the module), or the module refused the login.
    /// </exception>
    /// <exception cref="Pkcs11SessionException">
    /// An SO login while the library has a read-only session open on the slot (<c>CKR_SESSION_READ_ONLY_EXISTS</c>,
    /// refused before the module); or the anchor could not open because the token allows the application no more
    /// sessions (<c>CKR_SESSION_COUNT</c> from <c>C_OpenSession</c>, with a message giving the library's session tally
    /// on the slot). No <c>C_Login</c> is sent then.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or the login.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is disposed, or its disposal began before the hold was taken.</exception>
    public LoginHold Login(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (username is { Length: 0 })
            throw new ArgumentException("Username must not be empty.", nameof(username));
        string method = username is null ? OpLogin : OpLoginUser;

        // Created before the gate: it runs the caller's logger factory.
        ILoggerFactory? loggerFactory = owner.LoggerFactory;

        // A share of the login already held only needs the login to stay put, so it holds the gate shared
        // and leaves operations running; only a first login needs it exclusive.
        _gate.EnterReadLock();
        try
        {
            if (TryShareHeldLogin(owner, user, pin, username, method) is { } shared)
                return shared;
        }
        finally
        {
            _gate.ExitReadLock();
        }

        _gate.EnterWriteLock();
        try
        {
            // Another thread may have logged in between the two holds of the gate.
            if (TryShareHeldLogin(owner, user, pin, username, method) is { } shared)
                return shared;

            ThrowIfReadOnlySessionBlocksSo(user, method);

            Pkcs11SessionCore anchor = OpenAnchor(owner, user, loggerFactory);
            try
            {
                lock (_sendLock)
                    Send(anchor, user, pin, username);
            }
            catch
            {
                // Closing the only session this record opened also leaves the token public again.
                anchor.Dispose();
                throw;
            }

            lock (_lock)
            {
                // The owner's disposal began while the login was sent: its holds may already be released, so a
                // hold taken now would never be. Checked before the login is recorded, and undone below.
                if (!owner.IsDisposingOrDisposed)
                {
                    _anchor = anchor;
                    _user = user;
                    _username = username;
                    _generation++;
                    _logger = new CallOutFencedLogger((loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<TokenLoginRecord>());
                    return AddHolderLocked(owner);
                }
            }

            // Still under the gate held exclusive: nothing else saw this login. Log it back out (other sessions of
            // the application share it) and close the anchor.
            try
            {
                anchor.SendLogout();
            }
            catch (Pkcs11Exception)
            {
                // Closing the anchor below may end the login anyway; the owner's disposal is what is reported.
            }
            finally
            {
                anchor.Dispose();
            }
            throw OwnerDisposed();
        }
        finally
        {
            _gate.ExitWriteLock();
        }
    }

    // The share half of Login, under the gate (shared or exclusive): null when no one is logged in, or when the
    // send finds the login's anchor lost (the login then ended, and Login logs in afresh). Sends the
    // login on the anchor and accepts CKR_USER_ALREADY_LOGGED_IN, then takes a hold only if the login it was
    // sent for is still the current one: the module may have reported it ended meanwhile (MarkEnded does not
    // take the gate), and a hold stamped with the next generation would keep that one from ever logging out.
    private LoginHold? TryShareHeldLogin(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username, string method)
    {
        Pkcs11SessionCore? anchor;
        TokenUser? heldUser;
        string? heldUsername;
        long generation;
        lock (_lock)
        {
            anchor = _anchor;
            heldUser = _user;
            heldUsername = _username;
            generation = _generation;
        }

        if (anchor is null)
            return null;

        if (heldUser != user || !string.Equals(heldUsername, username, StringComparison.Ordinal))
        {
            // The usernames stay out of the message: it is commonly logged.
            throw new Pkcs11AuthenticationException(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, method,
                $"{method}: the token in slot {(ulong)_slotId} already has a {Describe(heldUser!.Value, heldUsername)} logged in " +
                "through this application, and a token holds one login at a time. Dispose every login and session that " +
                "holds it before logging in as someone else.");
        }

        // Shares run concurrently under the shared gate, so the sends on the anchor take turns here; the send then
        // waits for the anchor's lock if another thread holds it.
        try
        {
            lock (_sendLock)
                Send(anchor, user, pin, username);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            // Expected: this application holds the login, so the token says so. Not a PIN check.
        }
        catch (Exception ex) when (ex is Pkcs11Exception or ObjectDisposedException && !IsCurrent(generation))
        {
            // The anchor was lost (a token pulled and put back, an HSM failover): the send reported it and
            // AnchorLost ended that login, or another thread did and closed the anchor under this send. The
            // caller asked to log in, so log in from scratch: null sends Login on to a first login under the gate
            // held exclusive. The old generation stays ended: its holders inactive, its private handles refused.
            return null;
        }

        lock (_lock)
        {
            if (!ReferenceEquals(_anchor, anchor) || _generation != generation)
                throw LoginEnded();
            return AddHolderLocked(owner);
        }
    }

    /// <summary>
    /// Takes another share of the login <paramref name="existing"/> holds, without calling the module: for a
    /// session opened under a login, which keeps the login as long as it is open.
    /// </summary>
    /// <exception cref="ObjectDisposedException"><paramref name="existing"/> is released, or its login ended; or <paramref name="owner"/> is being disposed.</exception>
    public LoginHold Share(LoginHold existing, Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(owner);
        if (!ReferenceEquals(existing.Record, this))
            throw new ArgumentException("The hold belongs to another token's login.", nameof(existing));

        lock (_lock)
        {
            if (existing.IsReleased || _anchor is null || existing.Generation != _generation)
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
    /// <exception cref="ObjectDisposedException"><paramref name="hold"/> is released, or its login ended.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>; a lost anchor also ends the login.</exception>
    internal void InitUserPin(LoginHold hold, SecurePin? pin)
    {
        ArgumentNullException.ThrowIfNull(hold);

        // Shared, like an operation: the login cannot be logged out under the send. Lock order: the gate, then this
        // record's lock (released before the send), then the send lock, then the anchor's own, waited for.
        _gate.EnterReadLock();
        try
        {
            Pkcs11SessionCore anchor;
            lock (_lock)
            {
                if (hold.IsReleased || _anchor is null || hold.Generation != _generation)
                    throw LoginEnded();
                anchor = _anchor;
            }

            try
            {
                // Shares send their login on the anchor concurrently under the shared gate; take turns with them.
                lock (_sendLock)
                    anchor.SendInitPin(pin is null ? default : pin.Pin);
            }
            catch (ObjectDisposedException) when (!IsCurrent(hold.Generation))
            {
                // The module reported the login gone (MarkEnded does not take the gate) and the anchor was closed.
                throw LoginEnded();
            }
        }
        finally
        {
            _gate.ExitReadLock();
        }
    }

    /// <summary>
    /// Lends the anchor of the login <paramref name="hold"/> keeps as the working session of a
    /// <see cref="Pkcs11Login.OpenSession"/> whose <c>C_OpenSession</c> the module answered <c>CKR_SESSION_COUNT</c>:
    /// returns the borrowing core, or <see langword="null"/> with <paramref name="refusal"/> saying why it cannot be
    /// lent (it is lent already, or it is read-only and <paramref name="access"/> is read/write). Calls no module.
    /// </summary>
    /// <param name="hold">The share the new session will keep: it must be of the current login.</param>
    /// <param name="owner">The library the session comes through; its disposal reclaims the loan.</param>
    /// <param name="access">The access asked for: a read/write anchor serves either, a read-only one only <see cref="SessionAccess.ReadOnly"/>.</param>
    /// <param name="policy">The borrower's policy; <see langword="null"/> means <see cref="CryptoPolicy.Recommended"/>.</param>
    /// <param name="loggerFactory">The borrower's logger factory.</param>
    /// <param name="refusal">Why the anchor was not lent, for the <c>CKR_SESSION_COUNT</c> the caller throws.</param>
    /// <exception cref="ObjectDisposedException">
    /// <paramref name="hold"/> is released or its login ended; or <paramref name="owner"/> is being disposed.
    /// </exception>
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
        Log.AnchorReturned(logger, (ulong)_slotId, loan.SessionHandle);
    }

    /// <summary>
    /// Releases every share that came through <paramref name="owner"/>, as its disposal does; the shares
    /// become inactive, and if no share of the current login is left, it is logged out. First takes back the anchor
    /// if it is lent to a session that came through <paramref name="owner"/> (the borrower's return runs, and it is
    /// disposed), so the final logout never meets a lent anchor.
    /// </summary>
    /// <exception cref="InvalidOperationException">Called from inside an operation (<see cref="EnterOperation"/>).</exception>
    public void ReleaseHoldersOf(Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ThrowIfInsideOperation();

        AnchorLoan? reclaimed;
        lock (_lock)
            reclaimed = _loan is { } loan && ReferenceEquals(loan.Owner, owner) ? loan : null;

        // Outside the record's lock: the return takes the gate and the anchor's lock, and destroys the session objects
        // made through the borrower. It waits for an operation in flight on it.
        if (reclaimed is not null)
        {
            reclaimed.MarkReclaimed();
            reclaimed.Borrower.Dispose();
        }

        long generation;
        bool last;
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
            generation = _generation;
            last = released > 0 && _holders.Count == 0 && _anchor is not null;
        }

        if (last)
            LogOutIfUnheld(generation);
    }

    /// <summary>
    /// Records that the module reported the login gone (the anchor session lost, or <c>CKR_PIN_LOCKED</c> from
    /// a context-specific login): starts a new generation at once, so every existing share is inactive, no
    /// longer counts, and sends no <c>C_Logout</c>; and closes the anchor, so the next <see cref="Login"/>
    /// starts afresh.
    /// </summary>
    /// <param name="reason">The return code that reported it, for the log.</param>
    /// <remarks>Does not take the gate, so an operation that holds it shared may call this.</remarks>
    public void MarkEnded(CKR reason) => EndLogin(reason, onlyAnchor: null);

    // MarkEnded, or, with onlyAnchor, only while that session is the anchor (checked under the same hold of the
    // lock that ends the login).
    private void EndLogin(CKR reason, Pkcs11SessionCore? onlyAnchor)
    {
        Pkcs11SessionCore? anchor;
        ILogger logger;
        lock (_lock)
        {
            if (onlyAnchor is not null && !ReferenceEquals(_anchor, onlyAnchor))
                return;
            _generation++;
            _holders.Clear();
            // Before the anchor closes: its borrower refuses every call from now on, and its return sends nothing.
            EndLoanLocked();
            anchor = _anchor;
            _anchor = null;
            _user = null;
            _username = null;
            logger = _logger;
        }

        if (anchor is null)
            return;
        Log.TokenLoginEnded(logger, (ulong)_slotId, reason);
        anchor.Dispose();
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
    /// Holds the gate shared for an operation that relies on the login, so no login or final logout on the
    /// slot runs until the returned lease is disposed. Dispose it on the thread that took it.
    /// </summary>
    public IDisposable EnterOperation()
    {
        _gate.EnterReadLock();
        return new OperationLease(_gate);
    }

    /// <summary>
    /// Refuses a release on a thread inside an operation, before anything changes: the final logout needs the
    /// gate exclusive, which that thread cannot take while it holds it shared, and finding that out after the
    /// share was dropped would leave the login with no share to log it out.
    /// </summary>
    internal void ThrowIfInsideOperation()
    {
        if (_gate.IsReadLockHeld && !_gate.IsWriteLockHeld)
        {
            throw new InvalidOperationException(
                "A login cannot be released from inside an operation on its token: release the login outside the operation.");
        }
    }

    /// <summary>Releases one share, from <see cref="LoginHold.Dispose"/>; the last share of the current login logs out.</summary>
    internal void Release(LoginHold hold)
    {
        bool last;
        lock (_lock)
            last = _holders.Remove(hold) && _holders.Count == 0 && _anchor is not null && hold.Generation == _generation;

        if (last)
            LogOutIfUnheld(hold.Generation);
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
        var hold = new LoginHold(this, owner, _generation);
        _holders.Add(hold);
        return hold;
    }

    // The final logout. Takes the gate exclusive, so it waits for operations in flight, and checks again under
    // it: a login that shared the login, or a report that it ended, may have come in since the last share went.
    private void LogOutIfUnheld(long generation)
    {
        _gate.EnterWriteLock();
        try
        {
            Pkcs11SessionCore anchor;
            ILogger logger;
            lock (_lock)
            {
                if (_holders.Count != 0 || _anchor is null || _generation != generation)
                    return;
                // Not expected: a lent anchor has its borrower's hold. Should one be left, it is not lent any longer.
                EndLoanLocked();
                anchor = _anchor;
                _anchor = null;
                _user = null;
                _username = null;
                logger = _logger;
            }

            // Closing the anchor may itself end the login (it can be the application's last session), so a
            // failed C_Logout is logged and the anchor closed regardless.
            try
            {
                anchor.SendLogout();
            }
            catch (Pkcs11Exception ex)
            {
                Log.TokenLogoutFailed(logger, (ulong)_slotId, ex.ReturnValue);
            }
            catch (ObjectDisposedException)
            {
                Log.TokenLogoutAnchorClosed(logger, (ulong)_slotId);
            }
            finally
            {
                anchor.Dispose();
            }
        }
        finally
        {
            _gate.ExitWriteLock();
        }
    }

    // PKCS#11 v3.2 C_Login: an SO login fails with CKR_SESSION_READ_ONLY_EXISTS while the application has a
    // read-only session open. Refused here from the sessions the library has open through any load of the module
    // (decision 6); sessions opened outside the library are left to the module's answer.
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

    // Decision F of the anchor-lending addendum: the anchor could not open because the token allows this application
    // no more sessions. From the library's tally on the slot, which never counts sessions opened outside it.
    private Pkcs11Exception NoSessionForLogin(Pkcs11Exception moduleAnswer)
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

    private static ObjectDisposedException LoginEnded()
        => new(nameof(LoginHold), "This login has ended: it was disposed, logged out, or the module reported it gone. Log in again.");

    private static string Describe(TokenUser user, string? username)
        => (user == TokenUser.SecurityOfficer ? "Security Officer" : "normal user") + (username is null ? "" : " (named)");

    /// <summary>The shared hold of the gate an operation takes; released once.</summary>
    private sealed class OperationLease(ReaderWriterLockSlim gate) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
                gate.ExitReadLock();
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
