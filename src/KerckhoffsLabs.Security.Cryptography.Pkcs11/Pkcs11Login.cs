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
            return new Pkcs11Session(library, Slot, core, access, this, share);
        }
        catch
        {
            share.Dispose();
            throw;
        }
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
