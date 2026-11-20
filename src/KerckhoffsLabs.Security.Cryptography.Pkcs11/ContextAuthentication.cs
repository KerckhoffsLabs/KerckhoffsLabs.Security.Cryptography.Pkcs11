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
/// The library asks for the PIN before the operation takes its session, so a callback that fails leaves no operation
/// started, and a slow one holds up no other thread: no lock is held and no logout waits for it. It sends the PIN
/// after <c>C_*Init</c> succeeded and before the operation itself, on the operation's own session, once per operation.
/// A session with no source refuses an always-authenticate key before <c>C_*Init</c>. Keys without the attribute never
/// ask. This is not a token login: it does not change who is logged in, and it authenticates only the one operation.
/// A module that answers the context login with <c>CKR_OPERATION_NOT_INITIALIZED</c> (the key needs no
/// re-authentication for this operation, though it reports the attribute) carries on with the operation, unless the
/// session no longer shows the user logged in (OpenSC answers so once the card's login is gone): the token's login then
/// ends, and the operation fails with <c>CKR_USER_NOT_LOGGED_IN</c>.
/// </para>
/// <para>
/// A PIN the token refuses (<c>CKR_PIN_INCORRECT</c>, <c>CKR_PIN_INVALID</c>, <c>CKR_PIN_LEN_RANGE</c>) is never sent
/// again in a context login on the same token, whichever source, session or login it comes through: later operations
/// that bring the same PIN are refused before <c>C_*Init</c> with <see cref="Exceptions.Pkcs11AuthenticationException"/>,
/// so a stale PIN costs one retry, not one per key, per operation, per session or per request, even when a new source
/// is made for each request; sessions that send it at the same moment spend one too. The refusal holds for every key of
/// the token, unless it is the PIN the user's login held was made with: it is then this key's own refusal (a key with a
/// PIN of its own, such as a qualified signature key), and the user's PIN is still sent for the other keys. A context login that
/// succeeds with the PIN forgets its refusal for that key. A different PIN is sent. The library keeps no PIN for this,
/// only keyed digests (see <see cref="Pkcs11Slot.ForgetRefusedPins"/>).
/// </para>
/// <para>
/// <c>C_UnwrapKey</c>, <c>C_DeriveKey</c> (<see cref="Pkcs11Key.Derive(Mechanism, Objects.ObjectTemplate)"/>, ECDH
/// included) and <c>C_DecapsulateKey</c> start and finish in one call, so the specification gives no point at which to
/// re-authenticate them; they are sent as they are, with or without a source, and the token decides.
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
    /// It runs before the operation takes the key's session: it holds no lock of the library's, and no logout waits for
    /// it, so it may prompt, wait for another thread, log in or out of the token, or use the key's session.
    /// </para>
    /// <para>
    /// A PIN the token refused before in a context login is not sent again (see the class remarks): the operation is
    /// refused with <see cref="Exceptions.Pkcs11AuthenticationException"/> once the callback has returned it.
    /// </para>
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="pinFor"/> is <see langword="null"/>.</exception>
    /// <seealso cref="FromPin(SecurePin)"/>
    public static ContextAuthentication FromPinSource(Func<Pkcs11Key, SecurePin> pinFor)
    {
        ArgumentNullException.ThrowIfNull(pinFor);
        return new PinSource(pinFor);
    }

    /// <summary>
    /// <paramref name="pin"/>, for every key with <c>CKA_ALWAYS_AUTHENTICATE</c> that signs or decrypts: for a PIN the
    /// caller has at hand and keeps, such as the one its login was made with.
    /// </summary>
    /// <param name="pin">
    /// The PIN, read from a secret store; never a hardcoded value. The caller keeps ownership: the library never disposes
    /// it, and uses it for each operation, so it must stay undisposed while sessions that use this source sign or
    /// decrypt; an operation that finds it disposed is refused with <see cref="ObjectDisposedException"/>. Prefer
    /// <see cref="FromPinSource(Func{Pkcs11Key, SecurePin})"/> to read the PIN only when it is needed, and keep it in memory
    /// no longer.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> is <see langword="null"/>.</exception>
    public static ContextAuthentication FromPin(SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        return new FixedPin(pin);
    }

    /// <summary>
    /// The token's own pinpad, for tokens with <see cref="TokenFlags.ProtectedAuthenticationPath"/>: the context login
    /// is sent with <c>pPin = NULL_PTR</c>, and the user enters the PIN on the device for each operation.
    /// </summary>
    /// <remarks>
    /// On a token without <see cref="TokenFlags.ProtectedAuthenticationPath"/>, an operation with an always-authenticate
    /// key is refused with <see cref="InvalidOperationException"/> before <c>C_*Init</c>: PKCS#11 gives
    /// <c>pPin = NULL_PTR</c> a meaning only on such a token, and elsewhere a module may count it as a wrong PIN.
    /// </remarks>
    public static ContextAuthentication Pinpad { get; } = new PinpadSource();

    /// <summary>Whether the PIN is entered on the device (<c>pPin = NULL_PTR</c>) rather than supplied.</summary>
    internal abstract bool IsPinpad { get; }

    /// <summary>
    /// The PIN for <paramref name="key"/>, from the caller's code, which owns nothing of it afterwards; the library
    /// disposes it. Not called for <see cref="Pinpad"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The caller's code returned no PIN.</exception>
    internal abstract SecurePin PinFor(Pkcs11Key key);

    /// <summary>Whether the library owns the PIN <see cref="PinFor"/> returns, and disposes it once sent.</summary>
    internal virtual bool OwnsPin => true;

    private sealed class FixedPin(SecurePin pin) : ContextAuthentication
    {
        internal override bool IsPinpad => false;

        internal override bool OwnsPin => false;

        internal override SecurePin PinFor(Pkcs11Key key)
            => pin.IsDisposed
                ? throw new ObjectDisposedException(nameof(SecurePin),
                    "The SecurePin passed to ContextAuthentication.FromPin(SecurePin) was disposed: it must stay alive " +
                    "while sessions that use it sign or decrypt.")
                : pin;
    }

    private sealed class PinSource(Func<Pkcs11Key, SecurePin> pinFor) : ContextAuthentication
    {
        internal override bool IsPinpad => false;

        internal override SecurePin PinFor(Pkcs11Key key)
            => pinFor(key) ?? throw new InvalidOperationException(
                "The ContextAuthentication PIN callback returned no PIN for a key with CKA_ALWAYS_AUTHENTICATE, so it " +
                "cannot be used. Return a SecurePin from the callback passed to ContextAuthentication.FromPinSource.");
    }

    private sealed class PinpadSource : ContextAuthentication
    {
        internal override bool IsPinpad => true;

        internal override SecurePin PinFor(Pkcs11Key key)
            => throw new InvalidOperationException("The pinpad takes the PIN on the device.");
    }
}
