namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Where the PIN comes from when a key with <c>CKA_ALWAYS_AUTHENTICATE</c> is used: the re-authentication
/// (<c>C_Login(CKU_CONTEXT_SPECIFIC)</c>) PKCS#11 v3.2 requires for every sign or decrypt with such a key.
/// </summary>
/// <remarks>
/// <para>
/// Set it on a <see cref="Pkcs11Login"/>, and every session that login opens afterwards starts with it, or on a
/// <see cref="Pkcs11Session"/> directly (<see cref="Pkcs11Session.ContextAuthentication"/>). A key always uses its
/// own session's source, so the <c>System.Security.Cryptography</c> adapters (<c>RSAPkcs11</c>, <c>ECDsaPkcs11</c>,
/// ...), which cannot take a PIN argument, work too; one component's PIN callback is never asked about another
/// session's keys.
/// </para>
/// <para>
/// The library asks for the PIN after the operation's <c>C_*Init</c> succeeded and before the operation itself, on
/// the operation's own session, once per operation. A session with no source refuses an always-authenticate key
/// before <c>C_*Init</c>. Keys without the attribute never ask. This is not a token login: it does not change who is
/// logged in, and it authenticates only the one operation.
/// </para>
/// <para>
/// <c>C_UnwrapKey</c> and <c>C_DecapsulateKey</c> start and finish in one call, so the specification gives no point at
/// which to re-authenticate them; they are sent as they are, and the token decides.
/// </para>
/// </remarks>
public abstract class ContextAuthentication
{
    private protected ContextAuthentication()
    {
    }

    /// <summary>
    /// The PIN from <paramref name="pinFor"/>, called with the key about to be used each time one with
    /// <c>CKA_ALWAYS_AUTHENTICATE</c> signs or decrypts.
    /// </summary>
    /// <param name="pinFor">
    /// <para>
    /// Returns a new <see cref="SecurePin"/> for the key, read from a secret store or prompted for at that moment;
    /// never a hardcoded value. The library takes ownership: it disposes (zeroes) the PIN as soon as it is sent, so
    /// return a fresh instance every time, never one you keep. Returning <see langword="null"/> refuses the
    /// operation with <see cref="InvalidOperationException"/>; an exception it throws propagates, and the operation
    /// is abandoned.
    /// </para>
    /// <para>
    /// It runs while the operation holds the key's session, and the token's login open: a slow prompt delays the final
    /// logout on that token (which waits for operations in flight), never other operations or logins.
    /// </para>
    /// <para>
    /// It must not use the key's session: that is not allowed, and not enforced, so doing it interleaves calls
    /// inside the operation in progress. It may release a login on that token (the logout then waits for the
    /// operation), and may log in, except while the previous login's logout waits for this very operation, which is
    /// refused with <see cref="InvalidOperationException"/>. It must not wait for another thread's work on the same
    /// token: that thread may be waiting for this operation.
    /// </para>
    /// <para>
    /// When the token refuses the PIN it returns (<c>CKR_PIN_INCORRECT</c>), the session does not ask this source again:
    /// later operations with such a key are refused (<see cref="Exceptions.Pkcs11AuthenticationException"/>) until
    /// <see cref="Pkcs11Session.ContextAuthentication"/> is set again, so a stale PIN costs one retry, not every one.
    /// </para>
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="pinFor"/> is <see langword="null"/>.</exception>
    public static ContextAuthentication FromPin(Func<Pkcs11Key, SecurePin> pinFor)
    {
        ArgumentNullException.ThrowIfNull(pinFor);
        return new PinSource(pinFor);
    }

    /// <summary>
    /// The token's own pinpad, for tokens with <see cref="TokenFlags.ProtectedAuthenticationPath"/>: the context login
    /// is sent with <c>pPin = NULL_PTR</c>, and the user enters the PIN on the device for each operation.
    /// </summary>
    public static ContextAuthentication Pinpad { get; } = new PinpadSource();

    /// <summary>Whether the PIN is entered on the device (<c>pPin = NULL_PTR</c>) rather than supplied.</summary>
    internal abstract bool IsPinpad { get; }

    /// <summary>
    /// The PIN for <paramref name="key"/>, from the caller's code, which owns nothing of it afterwards; the library
    /// disposes it. Not called for <see cref="Pinpad"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The caller's code returned no PIN.</exception>
    internal abstract SecurePin PinFor(Pkcs11Key key);

    private sealed class PinSource(Func<Pkcs11Key, SecurePin> pinFor) : ContextAuthentication
    {
        internal override bool IsPinpad => false;

        internal override SecurePin PinFor(Pkcs11Key key)
            => pinFor(key) ?? throw new InvalidOperationException(
                "The ContextAuthentication PIN callback returned no PIN for a key with CKA_ALWAYS_AUTHENTICATE, so it " +
                "cannot be used. Return a SecurePin from the callback passed to ContextAuthentication.FromPin.");
    }

    private sealed class PinpadSource : ContextAuthentication
    {
        internal override bool IsPinpad => true;

        internal override SecurePin PinFor(Pkcs11Key key)
            => throw new InvalidOperationException("The pinpad takes the PIN on the device.");
    }
}
