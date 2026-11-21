namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// How a token login authenticates: a PIN the caller has at hand, a source the PIN is read from when it is needed, or
/// the token's protected authentication path (a pinpad). For <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/>
/// and <see cref="Pkcs11Slot.ShareOrLogin(LoginCredential, string?)"/>.
/// </summary>
/// <remarks>
/// A <see cref="SecurePin"/> converts to a credential implicitly, as <see cref="FromPin(SecurePin)"/>, so
/// <c>slot.Login(TokenUser.User, pin)</c> needs no wrapping. A credential holds no secret of its own: it refers to the
/// caller's PIN or source, and its <see cref="ToString"/> says only which kind it is.
/// </remarks>
public abstract class LoginCredential
{
    private protected LoginCredential()
    {
    }

    /// <summary>
    /// <paramref name="pin"/>, which the caller has at hand and keeps: the library never disposes it.
    /// </summary>
    /// <param name="pin">The PIN, read from a secret store; never a hardcoded value. The caller keeps ownership.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> is <see langword="null"/>.</exception>
    public static LoginCredential FromPin(SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        return new FixedPin(pin);
    }

    /// <summary>
    /// The PIN <paramref name="pinSource"/> returns, read only when a PIN is to be sent. The library disposes it once
    /// done with it, sent or not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For <see cref="Pkcs11Slot.ShareOrLogin(LoginCredential, string?)"/>, the source runs only when no login is held to
    /// share, outside every lock of the library: it may take its time (a prompt) or wait for other threads, and a login
    /// made meanwhile is shared and the PIN disposed unsent. For <see cref="Pkcs11Slot.Login(TokenUser, LoginCredential, string?)"/>,
    /// it runs once before the login, also outside every lock.
    /// </para>
    /// <para>
    /// It must return a new <see cref="SecurePin"/> each time, never one the caller keeps. Returning
    /// <see langword="null"/> or a disposed PIN fails the login with <see cref="InvalidOperationException"/>; an
    /// exception it throws propagates.
    /// </para>
    /// </remarks>
    /// <param name="pinSource">Returns the PIN, from a secret store; called at most once per login.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pinSource"/> is <see langword="null"/>.</exception>
    public static LoginCredential FromPinSource(Func<SecurePin> pinSource)
    {
        ArgumentNullException.ThrowIfNull(pinSource);
        return new PinSource(pinSource);
    }

    /// <summary>
    /// The token's protected authentication path (a pinpad or other reader of its own), for tokens with
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>: no PIN goes through the library. A token without one is
    /// refused before the module, with <see cref="InvalidOperationException"/>.
    /// </summary>
    public static LoginCredential Pinpad { get; } = new PinpadPath();

    /// <summary>The caller's <paramref name="pin"/>, as <see cref="FromPin(SecurePin)"/>.</summary>
    /// <param name="pin">The PIN; the caller keeps ownership.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> is <see langword="null"/>.</exception>
    public static implicit operator LoginCredential(SecurePin pin) => FromPin(pin);

    /// <summary>Which kind of credential this is; never the PIN.</summary>
    /// <returns><c>LoginCredential{Pin}</c>, <c>LoginCredential{PinSource}</c> or <c>LoginCredential{Pinpad}</c>.</returns>
    public abstract override string ToString();

    internal sealed class FixedPin(SecurePin pin) : LoginCredential
    {
        internal SecurePin Pin { get; } = pin;

        public override string ToString() => "LoginCredential{Pin}";
    }

    internal sealed class PinSource(Func<SecurePin> source) : LoginCredential
    {
        internal Func<SecurePin> Source { get; } = source;

        public override string ToString() => "LoginCredential{PinSource}";
    }

    internal sealed class PinpadPath : LoginCredential
    {
        public override string ToString() => "LoginCredential{Pinpad}";
    }
}
