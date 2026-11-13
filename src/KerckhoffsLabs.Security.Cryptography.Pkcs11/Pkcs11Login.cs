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
    /// Opens a session with the token that keeps this login while it is open, even once this
    /// <see cref="Pkcs11Login"/> is disposed.
    /// </summary>
    /// <param name="access">
    /// <see cref="SessionAccess.ReadWrite"/> (the default) or <see cref="SessionAccess.ReadOnly"/>, the only kind
    /// a write-protected token accepts. A Security Officer login allows only read/write sessions.
    /// </param>
    /// <param name="policy">The crypto policy the session enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.Recommended"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>The open session; the caller disposes it. Disposing it closes it and never logs out.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="access"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">This login is no longer active (see <see cref="IsActive"/>).</exception>
    /// <exception cref="Pkcs11SessionException">A read-only session under a Security Officer login
    /// (<c>CKR_SESSION_READ_WRITE_SO_EXISTS</c>, refused before the module).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access = SessionAccess.ReadWrite, ICryptoPolicy? policy = null)
    {
        if (!Enum.IsDefined(access))
            throw new ArgumentOutOfRangeException(nameof(access), access, "Not a defined SessionAccess value.");

        Pkcs11Library library = Slot.Library;
        ObjectDisposedException.ThrowIf(library.IsDisposed, library);

        // Taken first, so the login cannot go between the session opening and the session holding it.
        LoginHold share = _hold.Record.Share(_hold, library);
        try
        {
            Pkcs11SessionCore core = Slot.OpenSessionCore(access == SessionAccess.ReadWrite, policy);
            core.ContextAuthentication = ContextAuthentication;
            return new Pkcs11Session(library, Slot, core, access, this, share);
        }
        catch
        {
            share.Dispose();
            throw;
        }
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
    /// This login is not the Security Officer's (<see cref="User"/>); refused before the module, which would answer
    /// <c>CKR_USER_NOT_LOGGED_IN</c>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login is no longer active (see <see cref="IsActive"/>).</exception>
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
    /// This login is not the Security Officer's (<see cref="User"/>); refused before the module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">This login is no longer active (see <see cref="IsActive"/>).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>. A lost session or token also ends the login.</exception>
    public void InitUserPinWithPinpad() => InitUserPin(null);

    private void InitUserPin(SecurePin? userPin)
    {
        // PKCS#11 v3.2 C_InitPIN: only in the "R/W SO Functions" state, else CKR_USER_NOT_LOGGED_IN.
        if (User != TokenUser.SecurityOfficer)
        {
            throw new InvalidOperationException(
                "Only a Security Officer login can set the normal user's PIN (C_InitPIN). Log in with " +
                "TokenUser.SecurityOfficer; to change the PIN of the user logged in, use Pkcs11Session.SetPinWithPin.");
        }

        _hold.Record.InitUserPin(_hold, userPin);
    }

    /// <summary>
    /// Releases this hold of the login. The last holder to go logs out: if sessions opened through
    /// <see cref="OpenSession"/> are still open, the login stays until they are disposed too. Idempotent.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Called from inside an operation on the same token (from code the library calls back during one): the
    /// final logout waits for operations to finish, so it cannot run from one. Nothing is released then.
    /// </exception>
    public void Dispose() => _hold.Dispose();
}
