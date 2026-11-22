using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A hold of this application's login to a token, from <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/> or
/// <see cref="Pkcs11Slot.ShareOrLogin(LoginCredential, string?)"/>, and the way to open
/// sessions that keep it.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 makes a login belong to the application and the token, shared by every session the application
/// has with it (v3.2, "Session management functions"). So this is not a login of its own: every
/// <see cref="Pkcs11Login"/> for the same user on the same token, from any <see cref="Pkcs11Library"/> loaded
/// from the same module, is a hold of one login. It is logged out (<c>C_Logout</c>) when the last holder
/// goes; the holders are these objects and the sessions opened through <see cref="OpenSession()"/>. Disposing
/// in any order is fine: a login disposed before its sessions stays logged in until the last of them is
/// disposed too.
/// </para>
/// <para>
/// Disposing the <see cref="Pkcs11Library"/> this came through releases it, and its sessions, without
/// waiting for them; holders from other libraries keep the login.
/// </para>
/// <para>
/// Thread-safe. The PIN it was made with is not kept; while a normal user's login made with a PIN is held, an
/// HMAC-SHA-256 of that PIN is, under a random key in process memory, to tell a stale PIN from a key's own in context
/// logins. It is dropped when the login ends or the PIN changes. Memory read meanwhile (a crash dump) holds both, enough
/// to find a short PIN by trying them all: see the security model guide.
/// </para>
/// </remarks>
public sealed class Pkcs11Login : IDisposable
{
    private readonly LoginHold _hold;

    // Set by Dispose: a call on a disposed login is the caller's bug, an ObjectDisposedException, never the token
    // event Pkcs11LoginEndedException reports.
    private volatile bool _disposed;

    internal Pkcs11Login(Pkcs11Slot slot, TokenUser user, string? username, LoginHold hold)
    {
        Slot = slot;
        User = user;
        Username = username;
        _hold = hold;
    }

    /// <summary>The slot whose token this login is to.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>Who is logged in.</summary>
    public TokenUser User { get; }

    /// <summary>
    /// The username of a <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/> login, or <see langword="null"/> for one without.
    /// The library never logs it.
    /// </summary>
    public string? Username { get; }

    /// <summary>
    /// Where the sessions this login opens from now on get the PIN for keys with <c>CKA_ALWAYS_AUTHENTICATE</c>, or
    /// <see langword="null"/> (the default) for none. Copied into each session when <see cref="OpenSession()"/> opens it,
    /// so changing it later leaves open sessions as they are; set <see cref="Pkcs11Session.ContextAuthentication"/> to
    /// change one of those. See <see cref="Pkcs11.ContextAuthentication"/>.
    /// </summary>
    /// <remarks>
    /// It belongs to this <see cref="Pkcs11Login"/> object, not to the token's login: another
    /// <see cref="Pkcs11Login"/> for the same login has its own, so one component's PIN callback is never asked about
    /// another's keys. A PIN the token refused before for a key is not sent again, whatever source brings it (see
    /// <see cref="Pkcs11.ContextAuthentication"/>).
    /// </remarks>
    /// <exception cref="ObjectDisposedException">This login is disposed.</exception>
    public ContextAuthentication? ContextAuthentication
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return Volatile.Read(ref _contextAuthentication);
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Volatile.Write(ref _contextAuthentication, value);
        }
    }

    private ContextAuthentication? _contextAuthentication;

    /// <summary>
    /// Whether this hold still keeps the login: it is not disposed, its library is not disposed, and the login
    /// has not ended as far as the library knows.
    /// </summary>
    /// <remarks>
    /// Not a health check: the library learns that the module dropped the login only from a call that says so. After a
    /// token reinsertion or a network HSM's failover, this can read <see langword="true"/> until the next call on one of
    /// the login's sessions (or the next <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/>, which probes the login's
    /// own session) reports the loss. Use the key, or the session, and handle the exception.
    /// </remarks>
    public bool IsActive => _hold.IsActive;

    /// <summary>
    /// A task that completes once the library is done with the login this hold keeps: its <c>C_Logout</c> sent after
    /// its last holder went (whatever the module answered), or the login reported gone by the module (its session
    /// lost, the PIN locked). <see cref="Dispose"/> may return before the logout, which waits for the operations in
    /// flight on the token; await this to know it has run. Completed already when this hold's login is not the current
    /// one.
    /// </summary>
    /// <remarks>
    /// It does not prove the token is logged out. A <c>C_Logout</c> that failed, or the login's session lost while
    /// other sessions of the application kept the token logged in, can leave the login on the token: the library
    /// logs it out at once on another session of the slot where the module reports it still there, and failing that
    /// at the next first login. Private handles of the ended login are refused either way.
    /// </remarks>
    public Task Ended => _hold.Record.WhenEnded(_hold.Generation);

    /// <summary>
    /// Opens a session with the token that keeps this login while it is open, even once this
    /// <see cref="Pkcs11Login"/> is disposed: read/write where the token allows it, read-only where it does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read-only where the token refuses read/write: a write-protected token, one whose login session had to be
    /// read-only, or one with no read/write session left for this application and the login's own session lent
    /// already. Read <see cref="Pkcs11Session.Access"/> for which, or pass the access to
    /// <see cref="OpenSession(SessionAccess)"/> to get exactly that or a refusal. A Security Officer
    /// login allows only read/write sessions.
    /// </para>
    /// <para>
    /// Otherwise as <see cref="OpenSession(SessionAccess)"/>: see its remarks on the login's own
    /// session, lent on a token that allows no more sessions.
    /// </para>
    /// </remarks>
    /// <returns>
    /// The open session, under the library's crypto policy (<see cref="Pkcs11Library.Policy"/>); the caller disposes it. Disposing it closes it (or, for a lent session, hands it back) and
    /// releases its hold: it logs out only when it is the login's last holder.
    /// </returns>
    /// <exception cref="Pkcs11LoginEndedException">
    /// The login has ended: logged out, its logout pending (its last holder gone, the logout waiting for operations in
    /// flight), or reported gone by the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login, or the library it came through, is disposed.</exception>
    /// <exception cref="Pkcs11SessionException">
    /// <c>CKR_SESSION_COUNT</c>, from the module, when the token allows no more sessions and the login's own session
    /// is lent already (dispose that session first); the message says so.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession() => Open(access: null);

    /// <summary>
    /// Opens a session with the token, read-only or read/write as <paramref name="access"/> says, that keeps this login
    /// while it is open, even once this <see cref="Pkcs11Login"/> is disposed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The login keeps a session of its own with the token. On a token that allows this application no more sessions
    /// (<c>C_OpenSession</c> answers <c>CKR_SESSION_COUNT</c>; the token's advertised limits are not consulted, as they
    /// are optional and not always right), that session is <b>lent</b> as the session returned: a token that allows
    /// one session can still be used with a login, one working session at a time. A lent session is used like any
    /// other, with its own <see cref="Pkcs11Session.UsePolicy"/> leases and <see cref="Pkcs11Session.ContextAuthentication"/>, and
    /// <see cref="Pkcs11Session.GetSessionInfo"/> answers for the login's session, the module's truth. It is lent only
    /// for the access it has: a <see cref="SessionAccess.ReadOnly"/> request is refused where the login's session is
    /// read/write (use <see cref="OpenSession()"/>, which takes it as it is). Disposing it hands the session back to the login (see
    /// <see cref="Pkcs11Session.Dispose"/>), and a later call lends it again. While it is lent, the login's own sends on
    /// it (<see cref="InitUserPinWithPin"/>, the final logout) wait for the
    /// operation in flight on it, and its operations wait for them.
    /// </para>
    /// <para>
    /// On a module without <c>C_SessionCancel</c>, an operation a lent session abandoned (a failure partway through
    /// a sign, say) can make a later <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/> or <see cref="InitUserPinWithPin"/> answer
    /// <c>CKR_OPERATION_ACTIVE</c>: dispose the login's sessions and the login, and log in again.
    /// </para>
    /// </remarks>
    /// <param name="access">
    /// <see cref="SessionAccess.ReadWrite"/>, refused where the token does not allow it, or
    /// <see cref="SessionAccess.ReadOnly"/>, the only kind a write-protected token accepts. A Security Officer login
    /// allows only read/write sessions. <see cref="OpenSession()"/> picks read/write where the token
    /// allows it instead.
    /// </param>
    /// <returns>
    /// The open session, under the library's crypto policy (<see cref="Pkcs11Library.Policy"/>); the caller disposes it. Disposing it closes it (or, for a lent session, hands it back) and
    /// releases its hold: it logs out only when it is the login's last holder.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="access"/> is not a defined value.</exception>
    /// <exception cref="Pkcs11LoginEndedException">
    /// The login has ended: logged out, its logout pending (its last holder gone, the logout waiting for operations in
    /// flight), or reported gone by the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login, or the library it came through, is disposed.</exception>
    /// <exception cref="Pkcs11SessionException">
    /// A read-only session under a Security Officer login (<c>CKR_SESSION_READ_WRITE_SO_EXISTS</c>, refused before the
    /// module). Or <c>CKR_SESSION_COUNT</c>, from the module, when the token allows no more sessions and the login's
    /// own session cannot be lent: it is lent already (dispose that session first), or its access is not
    /// <paramref name="access"/> (open the session with <see cref="OpenSession()"/>, or with its access); the message
    /// says which.
    /// </exception>
    /// <exception cref="Pkcs11TokenException">
    /// <c>CKR_TOKEN_WRITE_PROTECTED</c>: asked for <see cref="SessionAccess.ReadWrite"/>, the module opened a read-only
    /// session, which is closed: the session is of the access asked for, or none.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access)
    {
        if (!Enum.IsDefined(access))
            throw new ArgumentOutOfRangeException(nameof(access), access, "Not a defined SessionAccess value.");
        return Open(access);
    }

    // Both OpenSession overloads: access as asked, or null for read/write where the token allows it.
    private Pkcs11Session Open(SessionAccess? access)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Pkcs11Library library = Slot.Library;
        ObjectDisposedException.ThrowIf(library.IsDisposed, library);

        // Taken first, so the login cannot go between the session opening and the session holding it. Both the share
        // and the core are released if anything fails (the core first), and handed to the session once it is built.
        ICryptoPolicy policy = library.Policy;
        using var share = new Owned<LoginHold>(_hold.Record.Share(_hold, library));
        using var core = new Owned<Pkcs11SessionCore>(access is { } requested
            ? OpenCore(share.Value, library, requested, policy, exact: true)
            : OpenDefaultCore(share.Value, library, policy));

        core.Value.ContextAuthentication = Volatile.Read(ref _contextAuthentication);
        SessionAccess actual = core.Value.IsReadWrite ? SessionAccess.ReadWrite : SessionAccess.ReadOnly;
        var session = new Pkcs11Session(library, Slot, core.Value, actual, this, share.Value);
        core.Release();
        share.Release();
        return session;
    }

    // The default access: read/write where the token allows it. The login's own session tells: it fell back to
    // read-only where the token refused read/write. A token write-protected since, or with no read/write session left
    // and the login's own session not lendable, is answered read-only too.
    private Pkcs11SessionCore OpenDefaultCore(LoginHold share, Pkcs11Library library, ICryptoPolicy policy)
    {
        if (_hold.Record.Anchor is { IsReadWrite: false })
            return OpenCore(share, library, SessionAccess.ReadOnly, policy, exact: false);
        try
        {
            return OpenCore(share, library, SessionAccess.ReadWrite, policy, exact: false);
        }
        catch (Pkcs11Exception ex) when (User == TokenUser.User
            && ex.ReturnValue is CKR.CKR_TOKEN_WRITE_PROTECTED or CKR.CKR_SESSION_COUNT)
        {
            // Write-protected, or no read/write session left and the login's own session not lendable (already lent):
            // a token that caps read/write sessions may still allow a read-only one. The SO has only read/write ones.
            return OpenCore(share, library, SessionAccess.ReadOnly, policy, exact: false);
        }
    }

    // The new session's core: a session of its own; or, where the token allows no further session of the kind asked
    // for, the login's own session, lent to it (Pkcs11SessionCore.Borrow). share is the new session's hold on the
    // login, which the loan is recorded against. With exact, the session has exactly the access asked for, or none: a
    // read-only one the module opened for read/write is refused, and so is lending a read/write login session for a
    // read-only request.
    private Pkcs11SessionCore OpenCore(LoginHold share, Pkcs11Library library, SessionAccess access, ICryptoPolicy policy,
        bool exact)
    {
        try
        {
            Pkcs11SessionCore core = Slot.OpenSessionCore(access == SessionAccess.ReadWrite, policy);
            return exact ? Slot.ExactAccess(core, access) : core;
        }
        catch (Pkcs11SessionException ex) when (ex.ReturnValue == CKR.CKR_SESSION_COUNT)
        {
            if (exact && access == SessionAccess.ReadOnly && _hold.Record.Anchor is { IsReadWrite: true })
            {
                throw new Pkcs11SessionException(CKR.CKR_SESSION_COUNT, Pkcs11Operations.OpOpenSession,
                    $"{Pkcs11Operations.OpOpenSession}: the token allows this application no further session, and the " +
                    "login's own session, which it would lend, is read/write, not the read-only one asked for. Open the " +
                    "session with OpenSession() (read/write where the token allows it) or SessionAccess.ReadWrite.", ex);
            }
            // The module's answer stays as the inner exception of a refusal. The token allows no further session
            // of the kind asked for: the login lends its own, if it can.
            return _hold.Record.TryLend(share, library, access, policy, library.LoggerFactory, out string? refusal)
                ?? throw new Pkcs11SessionException(CKR.CKR_SESSION_COUNT, Pkcs11Operations.OpOpenSession,
                    refusal!, ex);
        }
    }

    /// <summary>
    /// Takes another hold of this login, without a PIN and without calling the module: for handing the login to another
    /// component, which disposes its hold once done. The login stays until its last holder goes.
    /// </summary>
    /// <remarks>
    /// The new hold has no <see cref="ContextAuthentication"/> of its own until one is set: a component's PIN callback
    /// is never asked about another's keys.
    /// </remarks>
    /// <returns>The new hold.</returns>
    /// <exception cref="Pkcs11LoginEndedException">
    /// The login has ended: logged out, its logout pending (its last holder gone, the logout waiting for operations in
    /// flight), or reported gone by the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login, or the library it came through, is disposed.</exception>
    public Pkcs11Login Share()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Pkcs11Library library = Slot.Library;
        ObjectDisposedException.ThrowIf(library.IsDisposed, library);
        return new Pkcs11Login(Slot, User, Username, _hold.Record.Share(_hold, library));
    }

    /// <summary>
    /// Sets the normal user's PIN (<c>C_InitPIN</c>), as the Security Officer this login is for. Sent on the
    /// login's own read/write session, the "R/W SO Functions" state PKCS#11 v3.2 requires, so no session need be
    /// open.
    /// </summary>
    /// <param name="userPin">
    /// The new normal-user PIN. Read from a secret store at the point of use rather than hardcoded; the library
    /// neither keeps nor logs it.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="userPin"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// This login is not the Security Officer's (<see cref="User"/>): refused before the module, which would answer
    /// <c>CKR_USER_NOT_LOGGED_IN</c>.
    /// </exception>
    /// <exception cref="Pkcs11LoginEndedException">
    /// The login has ended: logged out, its logout pending (its last holder gone, the logout waiting for operations in
    /// flight), or reported gone by the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login, or the library it came through, is disposed.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Propagated from <c>C_InitPIN</c> (a PIN the token's policy refuses, for instance). A lost session or token
    /// also ends the login.
    /// </exception>
    public void InitUserPinWithPin(SecurePin userPin)
    {
        ArgumentNullException.ThrowIfNull(userPin);
        InitUserPin(userPin);
    }

    /// <summary>
    /// Sets the normal user's PIN (<c>C_InitPIN</c>) on the token's own pinpad, as the Security Officer this login
    /// is for: for tokens with <see cref="TokenFlags.ProtectedAuthenticationPath"/>. PKCS#11 signals on-device entry
    /// with <c>pPin = NULL_PTR</c>. Sent on the login's own read/write session, as
    /// <see cref="InitUserPinWithPin"/> is.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// This login is not the Security Officer's (<see cref="User"/>): refused before the module, which would answer
    /// <c>CKR_USER_NOT_LOGGED_IN</c>. Or the token has no protected authentication path
    /// (<see cref="TokenFlags.ProtectedAuthenticationPath"/>), refused before the module, which may take a call without a
    /// PIN as a wrong or an empty one.
    /// </exception>
    /// <exception cref="Pkcs11LoginEndedException">
    /// The login has ended: logged out, its logout pending (its last holder gone, the logout waiting for operations in
    /// flight), or reported gone by the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login, or the library it came through, is disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetTokenInfo</c> or <c>C_InitPIN</c>. A lost session or token also ends the login.</exception>
    public void InitUserPinWithPinpad() => InitUserPin(null);

    private void InitUserPin(SecurePin? userPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ObjectDisposedException.ThrowIf(Slot.Library.IsDisposed, Slot.Library);
        // PKCS#11 v3.2 C_InitPIN: only in the "R/W SO Functions" state, else CKR_USER_NOT_LOGGED_IN.
        if (User != TokenUser.SecurityOfficer)
        {
            // A misuse of this login, not a state of the token: an ended login is Pkcs11LoginEndedException.
            throw new InvalidOperationException(
                $"{Pkcs11Operations.OpInitPIN}: only a Security Officer login can set the normal user's PIN. Log in with " +
                "TokenUser.SecurityOfficer; to change the PIN of the user logged in, use Pkcs11Session.SetPinWithPin.");
        }

        _hold.Record.InitUserPin(_hold, userPin);
    }

    /// <summary>
    /// Releases this hold of the login. The last holder to go logs out: if sessions opened through
    /// <see cref="OpenSession()"/> are still open, the login stays until they are disposed too. Idempotent, and never
    /// throws.
    /// </summary>
    /// <remarks>
    /// The logout waits for operations in flight on the token: when there are some (this called from code the library
    /// calls back during one, or another thread's), it is left pending and sent as the last of them ends, so this
    /// returns before the token is logged out. A <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/> made meanwhile waits for it.
    /// </remarks>
    public void Dispose()
    {
        _disposed = true;
        _hold.Dispose();
    }
}
