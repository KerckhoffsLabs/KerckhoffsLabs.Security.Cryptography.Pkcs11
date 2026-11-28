namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The context login (<c>C_Login(CKU_CONTEXT_SPECIFIC)</c>) one sign or decrypt with a <c>CKA_ALWAYS_AUTHENTICATE</c>
/// key sends: its source, and the PIN that source gave, fetched before the operation takes its session's lease.
/// Disposing it disposes (zeroes) the PIN, unless the caller keeps it (<see cref="ContextAuthentication.FromPin(SecurePin)"/>).
/// </summary>
/// <remarks>
/// The PIN callback is the caller's code, and may be slow (a prompt) or wait for other threads. Run before the lease, it
/// holds no session lock and is not counted on the token's operation gate: a logout never waits for it, and a thread it
/// waits for may log in or out of the token without waiting for it in turn.
/// </remarks>
internal sealed class ContextLogin : IDisposable
{
    private ContextLogin(ContextAuthentication source, SecurePin? pin, Pkcs11Key key, TimeSpan? refusedPinLifetime)
    {
        Source = source;
        Pin = pin;
        Key = key;
        RefusedPinLifetime = refusedPinLifetime;
    }

    /// <summary>How long a refused PIN is kept from the token (<see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/>).</summary>
    internal TimeSpan? RefusedPinLifetime { get; }

    /// <summary>Where the PIN came from.</summary>
    internal ContextAuthentication Source { get; }

    /// <summary>The PIN, or <see langword="null"/> for the pinpad (<c>pPin = NULL_PTR</c>).</summary>
    internal SecurePin? Pin { get; }

    /// <summary>The key the operation uses.</summary>
    internal Pkcs11Key Key { get; }

    /// <summary>
    /// The context login for an operation with <paramref name="key"/>, from <paramref name="source"/>, its session's
    /// <see cref="ContextAuthentication"/>: called, before the operation's lease, only for a key that needs one.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="source"/> is <see langword="null"/>: refused before the module, which would let the operation
    /// start and answer <c>CKR_USER_NOT_LOGGED_IN</c> only at its end. Or the PIN callback returned no PIN, or a
    /// disposed one.
    /// </exception>
    internal static ContextLogin Prepare(Pkcs11Key key, ContextAuthentication? source, TimeSpan? refusedPinLifetime = null)
    {
        if (source is null)
        {
            throw new InvalidOperationException(
                "This key has CKA_ALWAYS_AUTHENTICATE, so the token wants the PIN again for each use, and its session " +
                "has no ContextAuthentication. Set Pkcs11Session.ContextAuthentication, or " +
                "Pkcs11Login.ContextAuthentication before opening the session, to ContextAuthentication.FromPin(...) or " +
                "ContextAuthentication.Pinpad.");
        }
        if (source.IsPinpad)
            return new ContextLogin(source, pin: null, key, refusedPinLifetime);

        SecurePin pin = source.PinFor(key);
        if (pin.IsDisposed)
        {
            throw new InvalidOperationException(
                "The ContextAuthentication PIN callback returned a disposed SecurePin. The library disposes the PIN it " +
                "is given once it is sent: return a new SecurePin from the callback every time, never one you keep.");
        }
        return new ContextLogin(source, pin, key, refusedPinLifetime);
    }

    // A PIN the caller keeps (ContextAuthentication.FromPin(SecurePin)) is not the library's to dispose.
    public void Dispose()
    {
        if (Source.OwnsPin)
            Pin?.Dispose();
    }
}
