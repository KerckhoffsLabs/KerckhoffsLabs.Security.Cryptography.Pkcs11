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
/// <c>C_Login</c>/<c>C_LoginUser</c> and <c>C_Logout</c> on it, and closes it after the final
/// <c>C_Logout</c>. It keeps the login alive while no other session is open, and is never handed out. It is
/// read/write for the SO (a read-only session would make the SO login fail) and read-only for the user (so a
/// write-protected token works).
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
/// delays operations on the slot, a slow pinpad on a share delays only other logins. The gate is recursive, so
/// a thread that holds it exclusive (sending a login on the anchor) can enter an operation; a thread inside an
/// operation cannot release a share (<see cref="ThrowIfInsideOperation"/>), since the last one needs it
/// exclusive.
/// </para>
/// <para>
/// Lock order: a session's lock, then the gate, then this record's lock; never the reverse. The lock the sends
/// on the anchor take turns on comes after the gate and is never held with the record's lock. No call into the
/// module is made under the record's lock.
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

    // All under _lock. Logged in exactly while _anchor is set.
    private Pkcs11SessionCore? _anchor;
    private TokenUser? _user;
    private string? _username;
    private long _generation;
    private ILogger _logger = NullLogger.Instance;

    internal TokenLoginRecord(NativeCULong slotId) => _slotId = slotId;

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

    /// <summary>The session the login was made on and is kept by, or <see langword="null"/> when not logged in.</summary>
    public Pkcs11SessionCore? Anchor
    {
        get { lock (_lock) return _anchor; }
    }

    /// <summary>Whether <paramref name="generation"/> is the current login, and it is still logged in.</summary>
    internal bool IsCurrent(long generation)
    {
        lock (_lock)
            return _anchor is not null && _generation == generation;
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
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or the login.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is disposed.</exception>
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
                _anchor = anchor;
                _user = user;
                _username = username;
                _generation++;
                _logger = new CallOutFencedLogger((loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<TokenLoginRecord>());
                return AddHolderLocked(owner);
            }
        }
        finally
        {
            _gate.ExitWriteLock();
        }
    }

    // The share half of Login, under the gate (shared or exclusive): null when no one is logged in. Sends the
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

        // Shares run concurrently under the shared gate; the anchor's own lease refuses a second thread rather
        // than waiting, so the sends on it take turns here.
        try
        {
            lock (_sendLock)
                Send(anchor, user, pin, username);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            // Expected: this application holds the login, so the token says so. Not a PIN check.
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
    /// <exception cref="ObjectDisposedException"><paramref name="existing"/> is released, or its login ended.</exception>
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
    /// Releases every share that came through <paramref name="owner"/>, as its disposal does; the shares
    /// become inactive, and if no share of the current login is left, it is logged out.
    /// </summary>
    /// <exception cref="InvalidOperationException">Called from inside an operation (<see cref="EnterOperation"/>).</exception>
    public void ReleaseHoldersOf(Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ThrowIfInsideOperation();

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
    public void MarkEnded(CKR reason)
    {
        Pkcs11SessionCore? anchor;
        ILogger logger;
        lock (_lock)
        {
            _generation++;
            _holders.Clear();
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

    // Under _lock.
    private LoginHold AddHolderLocked(Pkcs11Library owner)
    {
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

    private Pkcs11SessionCore OpenAnchor(Pkcs11Library owner, TokenUser user, ILoggerFactory? loggerFactory)
    {
        // Throws ObjectDisposedException for a disposed owner. The anchor survives that owner's disposal
        // (it is shared by every load of the module), so it calls through a view that outlives the load.
        return new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory)
            .OpenSessionCore(readWrite: user == TokenUser.SecurityOfficer, anchor: true);
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
