using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A hold of this application's login to a token, from <see cref="Pkcs11Slot.Login"/>,
/// <see cref="Pkcs11Slot.LoginWithPinpad"/> or <see cref="Pkcs11Slot.LoginUser"/>, and the way to open
/// sessions that keep it.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 makes a login belong to the application and the token, shared by every session the application
/// has with it (v3.2, "Session management functions"). So this is not a login of its own: every
/// <see cref="Pkcs11Login"/> for the same user on the same token, from any <see cref="Pkcs11Library"/> loaded
/// from the same module, is a hold of one login. It is logged out (<c>C_Logout</c>) when the last holder
/// goes; the holders are these objects and the sessions opened through <see cref="OpenSession"/>. Disposing
/// in any order is fine: a login disposed before its sessions stays logged in until the last of them is
/// disposed too.
/// </para>
/// <para>
/// Disposing the <see cref="Pkcs11Library"/> this came through releases it, and its sessions, without
/// waiting for them; holders from other libraries keep the login.
/// </para>
/// <para>
/// Thread-safe. The PIN it was made with is not kept.
/// </para>
/// </remarks>
public sealed class Pkcs11Login : IDisposable
{
    private readonly LoginHold _hold;

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
    /// The username of a <see cref="Pkcs11Slot.LoginUser"/> login, or <see langword="null"/> for one without.
    /// The library never logs it.
    /// </summary>
    public string? Username { get; }

    /// <summary>
    /// Where the sessions this login opens from now on get the PIN for keys with <c>CKA_ALWAYS_AUTHENTICATE</c>, or
    /// <see langword="null"/> (the default) for none. Copied into each session when <see cref="OpenSession"/> opens it,
    /// so changing it later leaves open sessions as they are; set <see cref="Pkcs11Session.ContextAuthentication"/> to
    /// change one of those. See <see cref="Pkcs11.ContextAuthentication"/>.
    /// </summary>
    /// <remarks>
    /// It belongs to this <see cref="Pkcs11Login"/> object, not to the token's login: another
    /// <see cref="Pkcs11Login"/> for the same login has its own, so one component's PIN callback is never asked about
    /// another's keys.
    /// </remarks>
    public ContextAuthentication? ContextAuthentication
    {
        get => Volatile.Read(ref _contextAuthentication);
        set => Volatile.Write(ref _contextAuthentication, value);
    }

    private ContextAuthentication? _contextAuthentication;

    /// <summary>
    /// Whether this hold still keeps the login: it is not disposed, its library is not disposed, and the login
    /// has not ended.
    /// </summary>
    public bool IsActive => _hold.IsActive;

    /// <summary>
    /// A task that completes once the login this hold keeps has ended: logged out (<c>C_Logout</c> sent) after its last
    /// holder went, or reported gone by the module. <see cref="Dispose"/> may return before the logout, which waits for
    /// the operations in flight on the token; await this for the guarantee that the token is logged out. Completed
    /// already when this hold's login is not the current one.
    /// </summary>
    public Task LoggedOut => _hold.Record.WhenEnded(_hold.Generation);

    /// <summary>
    /// Opens a session with the token that keeps this login while it is open, even once this
    /// <see cref="Pkcs11Login"/> is disposed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The login keeps a session of its own with the token. On a token that allows this application no more sessions
    /// (<c>C_OpenSession</c> answers <c>CKR_SESSION_COUNT</c>; the token's advertised limits are not consulted, as they
    /// are optional and not always right), that session is <b>lent</b> as the session returned: a token that allows
    /// one session can still be used with a login, one working session at a time. A lent session is used like any
    /// other, with its own <paramref name="policy"/> and <see cref="Pkcs11Session.ContextAuthentication"/>, and
    /// <see cref="Pkcs11Session.GetSessionInfo"/> answers for the login's session, the module's truth. Its
    /// <see cref="Pkcs11Session.Access"/> is the login session's: a read-only request served by a read/write session
    /// reads <see cref="SessionAccess.ReadWrite"/>. Disposing it hands the session back to the login (see
    /// <see cref="Pkcs11Session.Dispose"/>), and a later call lends it again. While it is lent, the login's own sends on
    /// it (<see cref="InitUserPinWithPin"/>, the final logout) wait for the
    /// operation in flight on it, and its operations wait for them.
    /// </para>
    /// <para>
    /// On a module without <c>C_SessionCancel</c>, an operation a lent session abandoned (a failure partway through
    /// a sign, say) can make a later <see cref="Pkcs11Slot.Login"/> or <see cref="InitUserPinWithPin"/> answer
    /// <c>CKR_OPERATION_ACTIVE</c>: dispose the login's sessions and the login, and log in again.
    /// </para>
    /// </remarks>
    /// <param name="access">
    /// <see cref="SessionAccess.ReadWrite"/> (the default) or <see cref="SessionAccess.ReadOnly"/>, the only kind
    /// a write-protected token accepts. A Security Officer login allows only read/write sessions.
    /// </param>
    /// <param name="policy">The crypto policy the session enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.Recommended"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>
    /// The open session; the caller disposes it. Disposing it closes it (or, for a lent session, hands it back) and
    /// releases its hold: it logs out only when it is the login's last holder.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="access"/> is not a defined value.</exception>
    /// <exception cref="Pkcs11LoginEndedException">This login is no longer active (see <see cref="IsActive"/>): released, or ended.</exception>
    /// <exception cref="ObjectDisposedException">The library this login came through is disposed.</exception>
    /// <exception cref="Pkcs11SessionException">
    /// A read-only session under a Security Officer login (<c>CKR_SESSION_READ_WRITE_SO_EXISTS</c>, refused before the
    /// module). Or <c>CKR_SESSION_COUNT</c>, from the module, when the token allows no more sessions and the login's
    /// own session cannot be lent: it is lent already (dispose that session first), or it is read-only and
    /// <paramref name="access"/> is read/write (open a <see cref="SessionAccess.ReadOnly"/> one); the message says which.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access = SessionAccess.ReadWrite, ICryptoPolicy? policy = null)
    {
        if (!Enum.IsDefined(access))
            throw new ArgumentOutOfRangeException(nameof(access), access, "Not a defined SessionAccess value.");

        Pkcs11Library library = Slot.Library;
        ObjectDisposedException.ThrowIf(library.IsDisposed, library);

        // Taken first, so the login cannot go between the session opening and the session holding it. Both the share
        // and the core are released if anything fails (the core first), and handed to the session once it is built.
        using var share = new Owned<LoginHold>(_hold.Record.Share(_hold, library));
        using var core = new Owned<Pkcs11SessionCore>(OpenCore(share.Value, library, access, policy));

        core.Value.ContextAuthentication = ContextAuthentication;
        SessionAccess actual = core.Value.IsReadWrite ? SessionAccess.ReadWrite : SessionAccess.ReadOnly;
        var session = new Pkcs11Session(library, Slot, core.Value, actual, this, share.Value);
        core.Release();
        share.Release();
        return session;
    }

    // The new session's core: a session of its own; or, where the token allows no further session of the kind asked
    // for, the login's own session, lent to it (Pkcs11SessionCore.Borrow). share is the new session's hold on the
    // login, which the loan is recorded against.
    private Pkcs11SessionCore OpenCore(LoginHold share, Pkcs11Library library, SessionAccess access, ICryptoPolicy? policy)
    {
        try
        {
            return Slot.OpenSessionCore(access == SessionAccess.ReadWrite, policy);
        }
        catch (Pkcs11SessionException ex) when (ex.ReturnValue == CKR.CKR_SESSION_COUNT)
        {
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
    /// <exception cref="Pkcs11LoginEndedException">This login is no longer active (see <see cref="IsActive"/>): released, or ended.</exception>
    /// <exception cref="ObjectDisposedException">The library this login came through is disposed.</exception>
    public Pkcs11Login Share()
    {
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
    /// <exception cref="Pkcs11AuthenticationException">
    /// This login is not the Security Officer's (<see cref="User"/>): <c>CKR_USER_NOT_LOGGED_IN</c>, refused before the
    /// module, which would answer the same.
    /// </exception>
    /// <exception cref="Pkcs11LoginEndedException">This login is no longer active (see <see cref="IsActive"/>): released, or ended.</exception>
    /// <exception cref="ObjectDisposedException">The library this login came through is disposed.</exception>
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
    /// <exception cref="Pkcs11AuthenticationException">
    /// This login is not the Security Officer's (<see cref="User"/>): <c>CKR_USER_NOT_LOGGED_IN</c>, refused before the
    /// module.
    /// </exception>
    /// <exception cref="Pkcs11LoginEndedException">This login is no longer active (see <see cref="IsActive"/>): released, or ended.</exception>
    /// <exception cref="ObjectDisposedException">The library this login came through is disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>. A lost session or token also ends the login.</exception>
    public void InitUserPinWithPinpad() => InitUserPin(null);

    private void InitUserPin(SecurePin? userPin)
    {
        // PKCS#11 v3.2 C_InitPIN: only in the "R/W SO Functions" state, else CKR_USER_NOT_LOGGED_IN.
        if (User != TokenUser.SecurityOfficer)
        {
            throw Pkcs11Exception.Create(CKR.CKR_USER_NOT_LOGGED_IN, Pkcs11Operations.OpInitPIN,
                $"{Pkcs11Operations.OpInitPIN}: only a Security Officer login can set the normal user's PIN. Log in with " +
                "TokenUser.SecurityOfficer; to change the PIN of the user logged in, use Pkcs11Session.SetPinWithPin.");
        }

        _hold.Record.InitUserPin(_hold, userPin);
    }

    /// <summary>
    /// Releases this hold of the login. The last holder to go logs out: if sessions opened through
    /// <see cref="OpenSession"/> are still open, the login stays until they are disposed too. Idempotent, and never
    /// throws.
    /// </summary>
    /// <remarks>
    /// The logout waits for operations in flight on the token: when there are some (this called from code the library
    /// calls back during one, or another thread's), it is left pending and sent as the last of them ends, so this
    /// returns before the token is logged out. A <see cref="Pkcs11Slot.Login"/> made meanwhile waits for it.
    /// </remarks>
    public void Dispose() => _hold.Dispose();
}
