using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// What a session knows of the login it was opened through (<see cref="Pkcs11Session.Login"/>): who is logged in, and
/// whether the session's hold of the login is still active. A view, not a hold: it cannot release, share or use the
/// login, so code handed a session gets no more authority over the login than the session itself has.
/// </summary>
public sealed class Pkcs11LoginInfo
{
    private readonly LoginHold _hold;

    internal Pkcs11LoginInfo(Pkcs11Slot slot, TokenUser user, string? username, LoginHold hold)
    {
        Slot = slot;
        User = user;
        Username = username;
        _hold = hold;
    }

    /// <summary>The slot whose token the login is to.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>Who is logged in.</summary>
    public TokenUser User { get; }

    /// <summary>The username of a <see cref="Pkcs11Slot.LoginUser"/> login, or <see langword="null"/>.</summary>
    public string? Username { get; }

    /// <summary>
    /// Whether the session's hold still keeps the login: the session is open, and the login has not ended.
    /// </summary>
    public bool IsActive => _hold.IsActive;
}
