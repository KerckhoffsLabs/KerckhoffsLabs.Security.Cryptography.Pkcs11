using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using System.Runtime.CompilerServices;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Represents a PKCS#11 slot: a logical reader or site that may hold a token. It is the entry
/// point for querying slot and token information and for opening sessions against the token it
/// contains.
/// </summary>
/// <remarks>
/// Two instances are equal when they name the same slot id of the same <see cref="Pkcs11Library"/>, so a
/// slot returned by <see cref="Pkcs11Library.WaitForSlotEvent"/> can be found in the list
/// <see cref="Pkcs11Library.GetSlotList"/> returned. The same id from another <see cref="Pkcs11Library"/>,
/// even one loaded from the same module, is another slot: it calls through, and stops working with, that
/// library.
/// </remarks>
public sealed class Pkcs11Slot : IEquatable<Pkcs11Slot>
{
    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// The factory this instance was constructed with (inherited from the owning
    /// <see cref="Pkcs11Library"/>), or <see langword="null"/> when the library was given none and
    /// nothing logs. Handed down to every <c>Pkcs11SessionCore</c> this slot opens.
    /// </summary>
    private readonly ILoggerFactory? _loggerFactory;

    /// <summary>
    /// The library this slot was listed by: what its sessions and logins come through.
    /// </summary>
    private readonly Pkcs11Library _library;

    /// <summary>
    /// Low level PKCS#11 wrapper of <see cref="_library"/>, taken when the slot was listed.
    /// </summary>
    private readonly LowLevelPkcs11Library _pkcs11Library;

    /// <summary>
    /// PKCS#11 handle of slot
    /// </summary>
    private readonly NativeCULong _slotId;

    /// <summary>
    /// Identifier of this slot (<c>CK_SLOT_ID</c>).
    /// </summary>
    public SlotId SlotId => new((ulong)_slotId);

    /// <summary>
    /// Initializes new instance of Pkcs11Slot class
    /// </summary>
    /// <param name="library">The library the slot is listed by.</param>
    /// <param name="slotId">PKCS#11 handle of slot</param>
    /// <param name="loggerFactory">
    /// Logger factory inherited from the owning <see cref="Pkcs11Library"/>; <see langword="null"/>
    /// for no logging.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="library"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="library"/> is disposed.</exception>
    internal Pkcs11Slot(Pkcs11Library library, ulong slotId, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(library);

        _loggerFactory = loggerFactory;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<Pkcs11Slot>();
        Log.SlotTrace(_logger, slotId, "ctor");

        _library = library;
        _pkcs11Library = library.LowLevelLibrary ?? throw new ObjectDisposedException(nameof(Pkcs11Library));
        _slotId = (NativeCULong)(slotId);
    }

    /// <summary>The library this slot was listed by.</summary>
    internal Pkcs11Library Library => _library;

    /// <summary>Whether <paramref name="other"/> is the same slot of the same <see cref="Pkcs11Library"/>.</summary>
    /// <param name="other">The slot to compare with.</param>
    /// <returns><see langword="true"/> if both name the same slot id through the same library.</returns>
    public bool Equals(Pkcs11Slot? other)
        => other is not null && ReferenceEquals(_library, other._library) && _slotId == other._slotId;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as Pkcs11Slot);

    /// <inheritdoc/>
    public override int GetHashCode()
        => HashCode.Combine(RuntimeHelpers.GetHashCode(_library), (ulong)_slotId);

    /// <summary>
    /// Obtains information about a particular slot in the system
    /// </summary>
    /// <returns>Slot information</returns>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetSlotInfo</c> call.</exception>
    public SlotInfo GetSlotInfo()
    {
        Log.SlotTrace(_logger, (ulong)_slotId, "GetSlotInfo");

        CKR rv = _pkcs11Library.C_GetSlotInfo(_slotId, out CK_SLOT_INFO slotInfo);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetSlotInfo);

        return new SlotInfo(_slotId, slotInfo);
    }

    /// <summary>
    /// Obtains information about a particular token in the system.
    /// </summary>
    /// <returns>Token information</returns>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetTokenInfo</c> call.</exception>
    public TokenInfo GetTokenInfo()
    {
        Log.SlotTrace(_logger, (ulong)_slotId, "GetTokenInfo");

        CKR rv = _pkcs11Library.C_GetTokenInfo(_slotId, out CK_TOKEN_INFO tokenInfo);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetTokenInfo);

        return new TokenInfo(_slotId, tokenInfo);
    }

    /// <summary>
    /// Obtains a list of mechanism types supported by a token.
    /// </summary>
    /// <remarks>
    /// Every mechanism the token reports is returned, including vendor-defined ones
    /// (<c>≥ CKM_VENDOR_DEFINED = 0x80000000</c>) and any standard mechanism newer than this enum.
    /// They are not filtered: the interop layer casts each value without validating it, precisely so
    /// those survive. The one exception is a value wider than 32 bits (legal where <c>CK_ULONG</c> is
    /// 64 bits), which <see cref="CKM"/> cannot hold and which is therefore left out of this list. Such an entry is a <see cref="CKM"/> value with no declared member, so it
    /// compares and round-trips correctly but has no name — <c>ToString()</c> renders the number, and
    /// <c>Enum.IsDefined</c> is what distinguishes it. Pass one to <see cref="Mechanism"/>'s
    /// <see langword="ulong"/> constructors to use it.
    /// </remarks>
    /// <returns>Read-only list of mechanism types supported by a token.</returns>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetMechanismList</c> call.</exception>
    public IReadOnlyList<CKM> GetMechanismList()
    {
        Log.SlotTrace(_logger, (ulong)_slotId, "GetMechanismList");

        CKR rv = _pkcs11Library.C_GetMechanismList(_slotId, [], out NativeCULong mechanismCount);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetMechanismList);

        if (mechanismCount < (NativeCULong)1)
            return [];

        CKM[] mechanismList = new CKM[ReportedLength.ForAllocation(mechanismCount, Pkcs11Operations.OpGetMechanismList)];
        rv = _pkcs11Library.C_GetMechanismList(_slotId, mechanismList, out mechanismCount);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetMechanismList);

        return ReportedLength.Items(mechanismList, mechanismCount, Pkcs11Operations.OpGetMechanismList);
    }

    /// <summary>
    /// Obtains information about a particular mechanism possibly supported by a token
    /// </summary>
    /// <param name="mechanism">Mechanism</param>
    /// <returns>Information about mechanism</returns>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetMechanismInfo</c> call.</exception>
    public MechanismInfo GetMechanismInfo(CKM mechanism)
    {
        Log.SlotTrace(_logger, (ulong)_slotId, "GetMechanismInfo");

        CKR rv = _pkcs11Library.C_GetMechanismInfo(_slotId, mechanism, out CK_MECHANISM_INFO mechanismInfo);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetMechanismInfo);

        return new MechanismInfo(mechanism, mechanismInfo);
    }

    /// <summary>
    /// Initializes the token in this slot with the Security Officer PIN and a
    /// human-readable label. After this call the token is in its factory state —
    /// any prior keys, certificates, or user PIN are destroyed.
    /// </summary>
    /// <param name="soPin">Security Officer's initial PIN. Caller retains
    /// ownership of the <see cref="SecurePin"/>; its bytes go to the native call
    /// straight out of the pinned buffer it owns, with no transient copy.</param>
    /// <param name="label">Token label. Encoded as UTF-8; must encode to 32
    /// bytes or fewer. PKCS#11 pads the label with ASCII spaces (0x20) to fill
    /// the on-token 32-byte field; it must NOT be null-terminated.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="soPin"/>
    /// or <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="label"/>
    /// encodes to more than 32 bytes of UTF-8.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying
    /// <c>C_InitToken</c> call.</exception>
    public void InitTokenWithPin(SecurePin soPin, string label)
    {
        ArgumentNullException.ThrowIfNull(soPin);
        ArgumentNullException.ThrowIfNull(label);

        Log.SlotTrace(_logger, (ulong)_slotId, "InitToken");

        // PKCS#11 v3.1 §11.5: pLabel points to a 32-byte field padded with
        // ASCII spaces (0x20) and must not be null-terminated.
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        if (labelBytes.Length > 32)
            throw new ArgumentException(
                $"Token label must encode to 32 UTF-8 bytes or fewer (got {labelBytes.Length}).",
                nameof(label));
        byte[] tokenLabel = new byte[32];
        Array.Fill(tokenLabel, (byte)0x20);
        Array.Copy(labelBytes, 0, tokenLabel, 0, labelBytes.Length);

        // The PIN goes to the native call straight out of the pinned buffer SecurePin owns;
        // no transient copy to zero. Matches Pkcs11SessionCore.Login's pattern.
        CKR rv = _pkcs11Library.C_InitToken(_slotId, soPin.Pin, tokenLabel);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpInitToken);
    }

    /// <summary>
    /// Initializes the token in this slot with the Security Officer PIN entered on the token's own
    /// pinpad, for tokens advertising <see cref="TokenFlags.ProtectedAuthenticationPath"/>. After
    /// this call the token is in its factory state — any prior keys, certificates, or user PIN are
    /// destroyed. PKCS#11 signals on-device PIN entry by calling <c>C_InitToken</c> with
    /// <c>pPin = NULL_PTR</c>.
    /// </summary>
    /// <param name="label">Token label. Encoded as UTF-8; must encode to 32
    /// bytes or fewer. PKCS#11 pads the label with ASCII spaces (0x20) to fill
    /// the on-token 32-byte field; it must NOT be null-terminated.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="label"/>
    /// encodes to more than 32 bytes of UTF-8.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying
    /// <c>C_InitToken</c> call.</exception>
    public void InitTokenWithPinpad(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        Log.SlotTrace(_logger, (ulong)_slotId, "InitToken (protected authentication path)");

        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        if (labelBytes.Length > 32)
            throw new ArgumentException(
                $"Token label must encode to 32 UTF-8 bytes or fewer (got {labelBytes.Length}).",
                nameof(label));
        byte[] tokenLabel = new byte[32];
        Array.Fill(tokenLabel, (byte)0x20);
        Array.Copy(labelBytes, 0, tokenLabel, 0, labelBytes.Length);

        CKR rv = _pkcs11Library.C_InitToken(_slotId, default, tokenLabel);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpInitToken);
    }

    /// <summary>
    /// Opens a session with the token that holds no login: it sees whatever login this application has on
    /// the token while there is one, but does not keep it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Login state belongs to the application and the token, not to a session (PKCS#11 v3.2, "Session
    /// management functions"): while a <see cref="Pkcs11Login"/> of this application's is active on the
    /// token, this session is in a user (or SO) state too, and its private objects are reachable. When the
    /// last holder of that login goes, it drops back to a public state, and handles of private objects found
    /// through it become invalid. Use <see cref="Pkcs11Login.OpenSession"/> for a session that keeps the login.
    /// </para>
    /// <para>
    /// Disposing the session closes it and never logs out.
    /// </para>
    /// </remarks>
    /// <param name="access">
    /// <see cref="SessionAccess.ReadOnly"/> (the default, least privilege, and the only kind a write-protected
    /// token accepts) or <see cref="SessionAccess.ReadWrite"/>.
    /// </param>
    /// <param name="policy">The crypto policy the session enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.Recommended"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>The open session; the caller disposes it.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="access"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access = SessionAccess.ReadOnly, ICryptoPolicy? policy = null)
    {
        ThrowIfUndefined(access);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Pkcs11SessionCore core = OpenSessionCore(access == SessionAccess.ReadWrite, policy);
        return new Pkcs11Session(_library, this, core, access);
    }

    /// <summary>
    /// Logs <paramref name="user"/> in to the token with <paramref name="pin"/>, or shares the login this
    /// application already has for that user, and returns this caller's hold of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A login belongs to the token and the whole application, and stays while any holder remains: the
    /// returned <see cref="Pkcs11Login"/> and every session opened through it. The last of them to be disposed
    /// logs out (<c>C_Logout</c>); disposing a session never does.
    /// </para>
    /// <para>
    /// Logging in for the user already logged in still sends the PIN; the token's
    /// <c>CKR_USER_ALREADY_LOGGED_IN</c> is accepted only because this application holds that login, and a token
    /// need not check the PIN then. Logging in as anyone else while a login is held is refused before the
    /// module (<c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>).
    /// </para>
    /// <para>
    /// The PIN is not kept: it is sent from <paramref name="pin"/>'s buffer and never copied or logged. Fetch it
    /// from a secret store rather than code or configuration.
    /// </para>
    /// </remarks>
    /// <param name="user">Who logs in: <see cref="TokenUser.User"/>, or <see cref="TokenUser.SecurityOfficer"/>.</param>
    /// <param name="pin">The PIN. The caller keeps ownership of it.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">Someone else is logged in, or the token refused the login.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or <c>C_Login</c>.</exception>
    public Pkcs11Login Login(TokenUser user, SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        return LoginCore(user, pin, username: null);
    }

    /// <summary>
    /// Logs <paramref name="user"/> in to the token through its protected authentication path (a pinpad or
    /// other reader of its own, for tokens with <see cref="TokenFlags.ProtectedAuthenticationPath"/>), or
    /// shares the login this application already has for that user. See <see cref="Login"/>.
    /// </summary>
    /// <param name="user">Who logs in.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">Someone else is logged in, or the token refused the login.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or <c>C_Login</c>.</exception>
    public Pkcs11Login LoginWithPinpad(TokenUser user) => LoginCore(user, pin: null, username: null);

    /// <summary>
    /// Logs a named <paramref name="user"/> in to the token (<c>C_LoginUser</c>, PKCS#11 v3.0), for tokens with
    /// user accounts, or shares the login this application already has for that same user and username. See
    /// <see cref="Login"/>.
    /// </summary>
    /// <remarks>
    /// The username is part of who is logged in: a login under another username, or a <see cref="Login"/>
    /// without one, is another user, refused before the module while this one is held. Usernames compare
    /// ordinally (exact, case-sensitive). The username is never logged.
    /// </remarks>
    /// <param name="user">Who logs in.</param>
    /// <param name="pin">The PIN. The caller keeps ownership of it.</param>
    /// <param name="username">The account name, sent UTF-8 encoded.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> or <paramref name="username"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">Someone else is logged in, or the token refused the login.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Propagated from <c>C_OpenSession</c> or <c>C_LoginUser</c>; <c>CKR_FUNCTION_NOT_SUPPORTED</c> from a module
    /// before v3.0.
    /// </exception>
    public Pkcs11Login LoginUser(TokenUser user, SecurePin pin, string username)
    {
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(username);
        if (username.Length == 0)
            throw new ArgumentException("Username must not be empty.", nameof(username));
        return LoginCore(user, pin, username);
    }

    private Pkcs11Login LoginCore(TokenUser user, SecurePin? pin, string? username)
    {
        ThrowIfUndefined(user);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Log.SlotTrace(_logger, (ulong)_slotId, username is null ? "Login" : "LoginUser");
        LoginHold hold = LoginRecord.Login(_library, user, pin, username);
        return new Pkcs11Login(this, user, username, hold);
    }

    /// <summary>The login record of this slot, shared by every load of the module.</summary>
    internal TokenLoginRecord LoginRecord => TokenLoginRegistry.Of(_pkcs11Library.Module).For(_slotId);

    private static void ThrowIfUndefined<T>(T value, [CallerArgumentExpression(nameof(value))] string? name = null)
        where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
            throw new ArgumentOutOfRangeException(name, value, $"Not a defined {typeof(T).Name} value.");
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot.
    /// </summary>
    /// <param name="readWrite">
    /// When <see langword="true"/> (the default), opens a read-write session
    /// (<c>CKF_SERIAL_SESSION | CKF_RW_SESSION</c>). When <see langword="false"/>, opens a
    /// read-only session — token-object creation will fail per PKCS#11 spec.
    /// </param>
    /// <param name="policy">The crypto policy the session enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.Recommended"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <param name="anchor">
    /// Whether this is the anchor session of the slot's login record: left open by the library's disposal,
    /// and able to call the module after it (see <see cref="LowLevelPkcs11Library.ForSessionOutlivingItsLoad"/>).
    /// </param>
    /// <returns>The opened session.</returns>
    internal Pkcs11SessionCore OpenSessionCore(bool readWrite = true, ICryptoPolicy? policy = null, bool anchor = false)
    {
        Log.SlotTrace(_logger, (ulong)_slotId, "OpenSessionCore");

        ulong flags = CKF.CKF_SERIAL_SESSION;
        if (readWrite)
            flags |= CKF.CKF_RW_SESSION;

        CKR rv = _pkcs11Library.C_OpenSession(_slotId, (NativeCULong)flags, out NativeCULong sessionId);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpOpenSession);

        // Counted before the handle exists and uncounted by its release, which runs exactly once however
        // the session closes (its owner, the library's disposal, the finalizer): so the tally never drifts.
        TokenLoginRegistry registry = TokenLoginRegistry.Of(_pkcs11Library.Module);
        NativeCULong slotId = _slotId;
        SessionAccess access = readWrite ? SessionAccess.ReadWrite : SessionAccess.ReadOnly;
        registry.SessionOpened(slotId, access);

        // Owned before any consumer code (the logger) runs, so a throw there closes the session
        // rather than leaving it open with nothing to close it.
        Pkcs11SessionHandle sessionHandle;
        try
        {
            sessionHandle = new Pkcs11SessionHandle(_pkcs11Library, sessionId, slotId, readWrite, anchor,
                released: () => registry.SessionClosed(slotId, access));
        }
        catch
        {
            registry.SessionClosed(slotId, access);
            throw;
        }

        // An invalid handle is never released, so its count goes here; the core refuses it below.
        if (sessionHandle.IsInvalid)
            registry.SessionClosed(slotId, access);

        try
        {
            Log.SessionOpened(_logger, readWrite ? "read-write" : "read-only", (ulong)sessionId, (ulong)_slotId,
                (policy ?? CryptoPolicy.Recommended).Name);

            LowLevelPkcs11Library calls = anchor ? _pkcs11Library.ForSessionOutlivingItsLoad() : _pkcs11Library;
            return new Pkcs11SessionCore(calls, _slotId, sessionHandle, _loggerFactory, policy);
        }
        catch
        {
            sessionHandle.Dispose();
            throw;
        }
    }
}
