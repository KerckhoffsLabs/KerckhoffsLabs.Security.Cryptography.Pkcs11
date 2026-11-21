using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The PINs a token refused, kept per slot so that the same PIN is never sent to the same token for the same purpose
/// twice: every wrong PIN costs one of the PIN's retries, and code that logs in once per request with a stale PIN from a
/// secret store would otherwise lock the PIN in as many requests as it has retries. One policy for every call that
/// sends a PIN the token checks: token logins (<c>C_Login</c>, <c>C_LoginUser</c>), context logins
/// (<c>CKU_CONTEXT_SPECIFIC</c>), the old PIN of <c>C_SetPIN</c> and the SO PIN of <c>C_InitToken</c>, whatever object
/// or delegate the PIN came through.
/// </summary>
/// <remarks>
/// <para>
/// No PIN is kept: only an HMAC-SHA-256 of it under a key drawn at random when the slot's record is made, kept in
/// memory only, and compared in constant time. A refused PIN's digest says nothing of the PIN that works. While a user
/// login made with a PIN is held, the digest of that PIN is kept too, to tell a stale PIN from a key's own one (below),
/// and dropped when the login ends or the PIN changes: memory read meanwhile (a crash dump) holds the key with it, which
/// is enough to find a short PIN by trying them all. No other PIN the token accepted is kept.
/// </para>
/// <para>
/// A refusal is scoped: to the token (its serial number and label, so a token swapped in is not judged by another's
/// refusals), and to what the PIN is for: the Security Officer, the user, a named user, or a context login. A context
/// login's refusal holds for all the token's keys (on most tokens the context PIN is the user's, so a stale one must cost
/// one retry, not one per key), unless it is the PIN the user's login held was made with: then the refusal holds for
/// this key only (a key with a PIN of its own, such as a qualified signature key), and the PIN is still sent for the
/// others, but only until a second key refuses it too (<see cref="RefuseContextPin"/>): two keys refusing the PIN the
/// login was made with is taken for that PIN changed since, outside the library, and the refusal then holds for all
/// the token's keys and the user's next login. So a PIN changed outside the library while a login made with it is held
/// costs at most two retries: one key's, then a second key's or the next login's. A key's own PIN sent by mistake to
/// another key is taken for a stale one. The normal user's login PIN (a named user's too) and the token-wide context
/// PIN are checked against each other's refusals (callers do): on most tokens they are one PIN, so a stale secret costs
/// one retry in all otherwise.
/// </para>
/// <para>
/// A refusal is forgotten only when it may have become wrong: the PIN accepted (a PIN changed outside the library to
/// one refused before), or set as the new PIN through this library (<c>C_SetPIN</c>, <c>C_InitPIN</c>); every PIN of the
/// user, or of the SO, when it is changed on the pinpad; every refusal when the token is initialized
/// (<c>C_InitToken</c>), or by <see cref="Pkcs11Slot.ForgetRefusedPins"/>, for a PIN changed outside the library; and,
/// with <see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/>, once that long has passed: the lifetime of the library that
/// recorded the refusal, whichever load of the module checks it later.
/// </para>
/// <para>
/// Sends are serialized per slot (<see cref="Serialized"/>): the check, the call and the record of its answer are one
/// step, so threads that send the same stale PIN at once cost one retry, not one each.
/// </para>
/// <para>
/// Bounded: past <see cref="Capacity"/> refusals the oldest is forgotten, which can cost one more retry, never fewer.
/// Kept for the life of the process, per module and slot (TokenLoginRegistry.RefusedPinsFor), across the module's
/// <c>C_Finalize</c>.
/// </para>
/// </remarks>
internal sealed class RefusedPins
{
    /// <summary>How many refusals are kept per slot.</summary>
    internal const int Capacity = 64;

    // Pinned, as the user PIN's digest is: the garbage collector never leaves a copy of either behind when it compacts.
    private readonly byte[] _key = NewKey();
    private readonly Lock _lock = new();
    private readonly Lock _send = new();
    private readonly List<Refusal> _refused = [];
    // The digest of the PIN the user's login held was made with, or null: no user login, or one made on the pinpad.
    private byte[]? _userPin;
    // The scope of the first key that refused _userPin during the login, or null.
    private byte[]? _userPinRefusedBy;
    // ForgetUserPin asked for while another thread was sending: done as that send ends.
    private bool _forgetUserPinAsked;

    /// <summary>What a PIN is for: a token login of a user, or a context login.</summary>
    [Flags]
    internal enum Purposes : byte
    {
        SecurityOfficer = 1,
        User = 2,
        Context = 4,
    }

    // Expires: the Clock reading past which the refusal no longer holds, or long.MaxValue.
    private sealed record Refusal(Purposes Purpose, byte[] Token, byte[] Scope, byte[] Pin, long Expires);

    /// <summary>
    /// The scope of a PIN: <paramref name="purpose"/> on the token identified by <paramref name="tokenIdentity"/>, for
    /// <paramref name="qualifier"/> (a username's UTF-8, a key's identity, or nothing).
    /// </summary>
    internal byte[] Scope(Purposes purpose, string tokenIdentity, ReadOnlySpan<byte> qualifier)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        Span<byte> header = [(byte)'S', (byte)purpose];
        hmac.AppendData(header);
        AppendWithLength(hmac, Encoding.UTF8.GetBytes(tokenIdentity));
        AppendWithLength(hmac, qualifier);
        return hmac.GetHashAndReset();
    }

    /// <summary>
    /// The scope of the context logins (<c>CKU_CONTEXT_SPECIFIC</c>) on the token identified by
    /// <paramref name="tokenIdentity"/> for all its keys: a stale PIN's.
    /// </summary>
    internal byte[] ContextScope(string tokenIdentity) => Scope(Purposes.Context, tokenIdentity, []);

    /// <summary>
    /// The scope of the context logins of one key (its class, key type, <c>CKA_ID</c> and <c>CKA_LABEL</c>) on the token
    /// identified by <paramref name="tokenIdentity"/>: a PIN the token accepts for other keys, refused for this one. Keys
    /// that share all four share it: a refusal of one holds for the others, which only keeps a PIN from them.
    /// </summary>
    internal byte[] KeyContextScope(string tokenIdentity, ulong objectClass, ulong keyType, ReadOnlySpan<byte> id, string? label)
    {
        byte[] labelBytes = label is null ? [] : Encoding.UTF8.GetBytes(label);
        byte[] qualifier = new byte[1 + 16 + 4 + id.Length + 1 + labelBytes.Length];
        qualifier[0] = (byte)'K';
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(qualifier.AsSpan(1), objectClass);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(qualifier.AsSpan(9), keyType);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(qualifier.AsSpan(17), id.Length);
        id.CopyTo(qualifier.AsSpan(21));
        qualifier[21 + id.Length] = label is null ? (byte)0 : (byte)1;
        labelBytes.CopyTo(qualifier.AsSpan(22 + id.Length));
        return Scope(Purposes.Context, tokenIdentity, qualifier);
    }

    /// <summary>
    /// Runs <paramref name="send"/> (a check, the call that sends a PIN, and the record of its answer) with every other
    /// such step on the slot held off, so two threads never both send a PIN that one of them is about to learn is wrong.
    /// </summary>
    internal void Serialized(Action send)
    {
        try
        {
            using (_send.EnterScope())
                send();
        }
        finally
        {
            ForgetUserPinIfAsked();
        }
    }

    /// <inheritdoc cref="Serialized(Action)"/>
    internal T Serialized<T>(Func<T> send)
    {
        try
        {
            using (_send.EnterScope())
                return send();
        }
        finally
        {
            ForgetUserPinIfAsked();
        }
    }

    private static byte[] NewKey()
    {
        byte[] key = GC.AllocateUninitializedArray<byte>(32, pinned: true);
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>
    /// Whether the token refused <paramref name="pin"/> in <paramref name="scope"/>, and the refusal has not expired
    /// (the lifetime it was recorded with).
    /// </summary>
    internal bool IsRefused(byte[] scope, ReadOnlySpan<byte> pin)
    {
        // The PIN checked is often the right one: its digest stays on the stack, zeroed once compared.
        Span<byte> digest = stackalloc byte[DigestLength];
        try
        {
            Digest(scope, pin, digest);
            long now = Clock();
            lock (_lock)
            {
                bool found = false;
                // Every entry compared, in constant time, whether or not one matched already.
                foreach (Refusal refusal in _refused)
                {
                    bool sameScope = CryptographicOperations.FixedTimeEquals(refusal.Scope, scope);
                    bool samePin = CryptographicOperations.FixedTimeEquals(refusal.Pin, digest);
                    bool current = now < refusal.Expires;
                    found |= sameScope && samePin && current;
                }
                return found;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>The time in milliseconds a refusal's age is measured with; a test seam.</summary>
    internal Func<long> Clock { get; set; } = static () => Environment.TickCount64;

    private const int DigestLength = 32;

    // The longest lifetime kept, in milliseconds: half the clock's range, so that adding it to the clock never overflows.
    private const long MaxLifetimeMilliseconds = long.MaxValue / 2;

    /// <summary>
    /// Records that the token identified by <paramref name="tokenIdentity"/> refused <paramref name="pin"/> in
    /// <paramref name="scope"/>, one of <paramref name="purpose"/>'s, for <paramref name="lifetime"/> when it is set
    /// (<see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/> of the library that sent it), else for good.
    /// </summary>
    internal void Refuse(Purposes purpose, string tokenIdentity, byte[] scope, ReadOnlySpan<byte> pin, TimeSpan? lifetime)
    {
        byte[] digest = new byte[DigestLength];
        Digest(scope, pin, digest);
        long expires = lifetime is { } kept ? Clock() + (long)Math.Min(kept.TotalMilliseconds, MaxLifetimeMilliseconds) : long.MaxValue;
        var refusal = new Refusal(purpose, TokenTag(tokenIdentity), scope, digest, expires);
        lock (_lock)
        {
            if (_refused.Count >= Capacity)
                _refused.RemoveAt(0);
            _refused.Add(refusal);
        }
    }

    /// <summary>
    /// Forgets the refusal of <paramref name="pin"/> in <paramref name="scope"/>, if any: the token accepted it there, or
    /// it was set as the PIN. Other refusals in the scope stand: those PINs are still wrong.
    /// </summary>
    internal void ForgetPin(byte[] scope, ReadOnlySpan<byte> pin)
    {
        // The PIN is the right one: its digest stays on the stack, zeroed once compared.
        Span<byte> digest = stackalloc byte[DigestLength];
        try
        {
            Digest(scope, pin, digest);
            lock (_lock)
            {
                for (int i = _refused.Count - 1; i >= 0; i--)
                {
                    if (CryptographicOperations.FixedTimeEquals(_refused[i].Scope, scope)
                        && CryptographicOperations.FixedTimeEquals(_refused[i].Pin, digest))
                    {
                        _refused.RemoveAt(i);
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>Forgets every refusal in <paramref name="scope"/>: its PIN was set on the pinpad, to one never seen.</summary>
    internal void Forget(byte[] scope)
    {
        lock (_lock)
            _refused.RemoveAll(refusal => CryptographicOperations.FixedTimeEquals(refusal.Scope, scope));
    }

    /// <summary>
    /// Forgets every refusal of <paramref name="purposes"/> on the token identified by <paramref name="tokenIdentity"/>:
    /// a PIN changed on the pinpad, whose new value the library never sees.
    /// </summary>
    internal void Forget(string tokenIdentity, Purposes purposes)
    {
        byte[] token = TokenTag(tokenIdentity);
        lock (_lock)
        {
            _refused.RemoveAll(refusal => (refusal.Purpose & purposes) != 0
                && CryptographicOperations.FixedTimeEquals(refusal.Token, token));
        }
    }

    /// <summary>Forgets every refusal: the token was initialized, or the application asked.</summary>
    internal void ForgetAll()
    {
        lock (_lock)
            _refused.Clear();
    }

    /// <summary>
    /// Records that the user's login to the token identified by <paramref name="tokenIdentity"/> was made with
    /// <paramref name="pin"/>, replacing any earlier one; kept until <see cref="ForgetUserPin"/>. Called under
    /// <see cref="Serialized"/>, so a context login sees the login's PIN either not yet or in full.
    /// </summary>
    internal void RememberUserPin(string tokenIdentity, ReadOnlySpan<byte> pin)
    {
        byte[] digest = GC.AllocateUninitializedArray<byte>(DigestLength, pinned: true);
        UserPinDigest(tokenIdentity, pin, digest);
        lock (_lock)
        {
            if (_userPin is { } earlier)
                CryptographicOperations.ZeroMemory(earlier);
            _userPin = digest;
            _userPinRefusedBy = null;
            // A forget asked for by the login before this one is done with.
            _forgetUserPinAsked = false;
        }
    }

    /// <summary>
    /// Records that a context login with <paramref name="pin"/> was refused for the key of <paramref name="keyScope"/> on
    /// the token identified by <paramref name="tokenIdentity"/>: for that key alone when it is the PIN the user's login
    /// held was made with and no other key refused it during that login (a key with a PIN of its own); else for all the
    /// token's keys (<paramref name="tokenScope"/>), a stale PIN's. Under <see cref="Serialized"/>.
    /// </summary>
    /// <returns>Whether the refusal holds for all the token's keys.</returns>
    internal bool RefuseContextPin(string tokenIdentity, byte[] tokenScope, byte[] keyScope, ReadOnlySpan<byte> pin,
        TimeSpan? lifetime)
    {
        bool keyOnly;
        bool userPin = IsUserPin(tokenIdentity, pin);
        if (userPin)
        {
            lock (_lock)
            {
                // A second key refusing the login's PIN: more likely that PIN changed outside the library while the
                // login held than two keys each with a PIN of its own. Taken for stale, so it costs no third retry.
                keyOnly = _userPinRefusedBy is null || CryptographicOperations.FixedTimeEquals(_userPinRefusedBy, keyScope);
                _userPinRefusedBy ??= keyScope;
            }
        }
        else
        {
            keyOnly = false;
        }
        Refuse(Purposes.Context, tokenIdentity, keyOnly ? keyScope : tokenScope, pin, lifetime);
        // Escalated: this key's refusal is kept too, as the first key's was, so a login that later shows the PIN is the
        // user's (forgetting its token-wide refusal) does not have it sent to this key again.
        if (userPin && !keyOnly)
            Refuse(Purposes.Context, tokenIdentity, keyScope, pin, lifetime);
        return !keyOnly;
    }

    /// <summary>Whether <paramref name="pin"/> is the PIN the user's login held on the token was made with.</summary>
    internal bool IsUserPin(string tokenIdentity, ReadOnlySpan<byte> pin)
    {
        Span<byte> digest = stackalloc byte[DigestLength];
        try
        {
            UserPinDigest(tokenIdentity, pin, digest);
            lock (_lock)
                return _userPin is { } known && CryptographicOperations.FixedTimeEquals(known, digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>Forgets the user's PIN: the login ended, or the PIN changed.</summary>
    /// <remarks>
    /// Never waits: while a send is in flight on another thread (<see cref="Serialized"/>), the PIN is forgotten as that
    /// send ends, so a context login sent with the login's PIN is judged against it, as a key's own refusal, even when
    /// the login ends meanwhile.
    /// </remarks>
    internal void ForgetUserPin()
    {
        // Asked first, then done if no send is in flight: a send that holds the lock now sees the request when it
        // ends (ForgetUserPinIfAsked).
        Volatile.Write(ref _forgetUserPinAsked, true);
        ForgetUserPinIfAsked();
    }

    // Forgets the user's PIN if that was asked for and no other thread is sending a PIN. Never waits.
    private void ForgetUserPinIfAsked()
    {
        if (!Volatile.Read(ref _forgetUserPinAsked) || !_send.TryEnter())
            return;
        try
        {
            lock (_lock)
            {
                if (!_forgetUserPinAsked)
                    return;
                _forgetUserPinAsked = false;
                if (_userPin is { } known)
                    CryptographicOperations.ZeroMemory(known);
                _userPin = null;
                _userPinRefusedBy = null;
            }
        }
        finally
        {
            _send.Exit();
        }
    }

    /// <summary>Whether the PIN of a user's login is remembered: a user login is held, or being made.</summary>
    internal bool RemembersUserPin
    {
        get { lock (_lock) return _userPin is not null && !_forgetUserPinAsked; }
    }

    /// <summary>The number of refusals kept, for tests.</summary>
    internal int Count
    {
        get { lock (_lock) return _refused.Count; }
    }

    /// <summary>
    /// The identity of a token a refusal is scoped to: its serial number and label, as the bytes the module reported
    /// (fields that are not UTF-8 can decode to the same text).
    /// </summary>
    internal static string TokenIdentity(TokenInfo info)
        => info.RawSerialNumber.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":"
            + info.RawSerialNumber + info.RawLabel;

    /// <summary>Whether <paramref name="rv"/> refuses a PIN, at the cost of one of its retries.</summary>
    internal static bool IsPinRefusal(CKR rv) => rv is CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_INVALID or CKR.CKR_PIN_LEN_RANGE;

    private byte[] TokenTag(string tokenIdentity)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        Span<byte> header = [(byte)'T'];
        hmac.AppendData(header);
        hmac.AppendData(Encoding.UTF8.GetBytes(tokenIdentity));
        return hmac.GetHashAndReset();
    }

    private void UserPinDigest(string tokenIdentity, ReadOnlySpan<byte> pin, Span<byte> digest)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        Span<byte> header = [(byte)'U'];
        hmac.AppendData(header);
        AppendWithLength(hmac, Encoding.UTF8.GetBytes(tokenIdentity));
        hmac.AppendData(pin);
        hmac.GetHashAndReset(digest);
    }

    private void Digest(byte[] scope, ReadOnlySpan<byte> pin, Span<byte> digest)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        Span<byte> header = [(byte)'P'];
        hmac.AppendData(header);
        hmac.AppendData(scope);
        hmac.AppendData(pin);
        hmac.GetHashAndReset(digest);
    }

    private static void AppendWithLength(IncrementalHash hmac, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hmac.AppendData(length);
        hmac.AppendData(value);
    }
}
