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
    /// The PKCS#11 URI (RFC 7512) of the token in this slot: its manufacturer, model, serial number and label, e.g.
    /// <c>pkcs11:manufacturer=SoftHSM%20project;model=SoftHSM%20v2;serial=8e1b2c3d4f5a6b7c;token=signing-prod</c>.
    /// Put its text (<see cref="Pkcs11Uri.ToString"/>) in configuration and find the token again with
    /// <see cref="Pkcs11Library.GetSlotByUri(string)"/>, wherever the module numbers its slot then; add the object
    /// attributes (<c>uri with { Object = "release-key", Type = CKO.CKO_PRIVATE_KEY }</c>) to name a key on it.
    /// </summary>
    /// <remarks>
    /// The serial number tells apart tokens that share a label, and the manufacturer and model tokens of different
    /// makes that share a serial number. A token whose fields are not unique even together cannot be told apart by any
    /// URI: <see cref="Pkcs11Library.GetSlotByUri(string)"/> then refuses rather than picks one.
    /// </remarks>
    /// <returns>The token's URI.</returns>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetTokenInfo</c> (<c>CKR_TOKEN_NOT_PRESENT</c> when the slot is empty).</exception>
    public Pkcs11Uri GetTokenUri() => Pkcs11Uri.ForToken(GetTokenInfo());

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
    /// <remarks>
    /// PKCS#11 v3.2 fails <c>C_InitToken</c> with <c>CKR_SESSION_EXISTS</c> while the application has a session open
    /// with the token. The library refuses it before the module while it has a session or a login (which keeps a
    /// session of its own) open on the slot through any load of the module. Sessions other applications have open
    /// are not known to it: the spec leaves the outcome then undefined, and some tokens refuse it.
    /// </remarks>
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
    /// <exception cref="Pkcs11SessionException">This application has a session or a login open on the token,
    /// through any load of the module (<c>CKR_SESSION_EXISTS</c>, refused before the module).</exception>
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

        ThrowIfSessionsExist();

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
    /// <remarks>
    /// Refused before the module while this application has any session or login on the token, as for
    /// <see cref="InitTokenWithPin"/>.
    /// </remarks>
    /// <param name="label">Token label. Encoded as UTF-8; must encode to 32
    /// bytes or fewer. PKCS#11 pads the label with ASCII spaces (0x20) to fill
    /// the on-token 32-byte field; it must NOT be null-terminated.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="label"/>
    /// encodes to more than 32 bytes of UTF-8.</exception>
    /// <exception cref="Pkcs11SessionException">This application has a session or a login open on the token,
    /// through any load of the module (<c>CKR_SESSION_EXISTS</c>, refused before the module).</exception>
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

        ThrowIfSessionsExist();

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
    /// <para>
    /// A login keeps a session of its own, and on a token that allows this application one session at a time it
    /// <b>lends</b> that session to its own <see cref="Pkcs11Login.OpenSession"/>. This method never lends: while a
    /// login holds the token's only session, a session opened here fails with <c>CKR_SESSION_COUNT</c> (use the login's
    /// <see cref="Pkcs11Login.OpenSession"/> instead). A session opened here also holds that only session against a
    /// <see cref="Login"/>, which fails with <c>CKR_SESSION_COUNT</c> until the session is disposed.
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
    /// <exception cref="Pkcs11SessionException">A read-only session while this application has the Security Officer
    /// logged in (<c>CKR_SESSION_READ_WRITE_SO_EXISTS</c>, refused before the module); or the token allows this
    /// application no more sessions (<c>CKR_SESSION_COUNT</c>, from the module). A login keeps a session of its own,
    /// so on a token that allows one session, a session opened while a login is held is refused: open it through the
    /// login (<see cref="Pkcs11Login.OpenSession"/>) instead, and the message says so.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access = SessionAccess.ReadOnly, ICryptoPolicy? policy = null)
    {
        ThrowIfUndefined(access);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Pkcs11SessionCore core = OpenSessionCore(access == SessionAccess.ReadWrite, policy);
        return new Pkcs11Session(_library, this, core, access);
    }

    /// <summary>
    /// Logs <paramref name="user"/> in to the token with <paramref name="pin"/>, and returns this caller's hold of the
    /// login.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A login belongs to the token and the whole application, and stays while any holder remains: the
    /// returned <see cref="Pkcs11Login"/> and every session opened through it. The last of them to be disposed
    /// logs out (<c>C_Logout</c>); disposing a session never does.
    /// </para>
    /// <para>
    /// A login while this application holds one on the token is refused before the module, and the PIN is not sent:
    /// <c>CKR_USER_ALREADY_LOGGED_IN</c> for the same user, <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c> for anyone else.
    /// PKCS#11 has no way to check a PIN against a login already made, so a second login that succeeded would succeed
    /// with any PIN. To use the login held, take a share of it without a PIN: <see cref="Pkcs11Login.Share"/> on a
    /// <see cref="Pkcs11Login"/> you were given, or <see cref="TryShareLogin(TokenUser, out Pkcs11Login?)"/> for the
    /// login held on this slot. A login whose own session was lost (a token pulled and put back, an HSM failover) has
    /// ended: the refusal checks that session first (<c>C_GetSessionInfo</c>), and logs in afresh instead.
    /// </para>
    /// <para>
    /// When the token answers that a user is logged in already although this application holds no login, the login is
    /// one the library left behind (its <c>C_Logout</c> failed, or its session was lost while others stayed open): it
    /// is logged out and the login sent once more, so the PIN is checked. A login made outside the library (another
    /// component calling the module directly) is never taken over: <see cref="Pkcs11AuthenticationException"/>.
    /// </para>
    /// <para>
    /// A logout waits for the operations in flight on the token (see <see cref="Pkcs11Login.Dispose"/>); a login while
    /// one is pending waits for it, then logs in afresh.
    /// </para>
    /// <para>
    /// The PIN is not kept: it is sent from <paramref name="pin"/>'s buffer and never copied or logged. Fetch it
    /// from a secret store rather than code or configuration.
    /// </para>
    /// <para>
    /// The first login opens a session of its own and keeps it until the last holder is disposed. It is read/write
    /// where the token allows (read-only for a <see cref="TokenUser.User"/> on a write-protected token, or when the
    /// token has no read/write session left for this application), so it counts against the token's session limits.
    /// On a token that allows this application no more sessions (a <see cref="OpenSession"/> session holds its only
    /// one) the login fails with <c>CKR_SESSION_COUNT</c> before any PIN is sent: dispose that session, or log in
    /// first and open sessions through the login.
    /// </para>
    /// <para>
    /// On a token that allows one session at a time, the login's own session is <b>lent</b> to
    /// <see cref="Pkcs11Login.OpenSession"/>, one working session at a time, so a login does not need a second session
    /// to work with. While it holds the token's only session, <see cref="OpenSession"/> fails with
    /// <c>CKR_SESSION_COUNT</c>: open the session through the login instead.
    /// </para>
    /// </remarks>
    /// <param name="user">Who logs in: <see cref="TokenUser.User"/>, or <see cref="TokenUser.SecurityOfficer"/>.</param>
    /// <param name="pin">The PIN. The caller keeps ownership of it.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">This application holds a login on the token already
    /// (<c>CKR_USER_ALREADY_LOGGED_IN</c> or <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>, refused before the module); the
    /// token is logged in outside the library; or the token refused the login.</exception>
    /// <exception cref="Pkcs11SessionException">A Security Officer login while this application has a read-only
    /// session open on the token (<c>CKR_SESSION_READ_ONLY_EXISTS</c>, refused before the module); or the login's
    /// own session could not open because the token allows this application no more sessions
    /// (<c>CKR_SESSION_COUNT</c>, from the module; no PIN is sent).</exception>
    /// <exception cref="InvalidOperationException">Called from inside an operation on the token while the previous
    /// login's logout waits for operations to finish.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or <c>C_Login</c>.</exception>
    public Pkcs11Login Login(TokenUser user, SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        return LoginCore(user, pin, username: null);
    }

    /// <summary>
    /// Logs <paramref name="user"/> in to the token through its protected authentication path (a pinpad or
    /// other reader of its own, for tokens with <see cref="TokenFlags.ProtectedAuthenticationPath"/>). See
    /// <see cref="Login"/>, which also describes the refusal while a login is held, how the login's session is lent on
    /// a token that allows one session, and the <c>CKR_SESSION_COUNT</c> cases.
    /// </summary>
    /// <param name="user">Who logs in.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">As for <see cref="Login"/>: a login is held already (the pinpad
    /// is not used then), the token is logged in outside the library, or the token refused the login.</exception>
    /// <exception cref="Pkcs11SessionException">As for <see cref="Login"/>: <c>CKR_SESSION_READ_ONLY_EXISTS</c>, or
    /// <c>CKR_SESSION_COUNT</c> when the login's own session could not open (the pinpad is not used then).</exception>
    /// <exception cref="InvalidOperationException">As for <see cref="Login"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or <c>C_Login</c>.</exception>
    public Pkcs11Login LoginWithPinpad(TokenUser user) => LoginCore(user, pin: null, username: null);

    /// <summary>
    /// Logs a named <paramref name="user"/> in to the token (<c>C_LoginUser</c>, PKCS#11 v3.0), for tokens with
    /// user accounts. See <see cref="Login"/>, which also describes the refusal while a login is held.
    /// </summary>
    /// <remarks>
    /// The username is part of who is logged in: a login under another username, or a <see cref="Login"/>
    /// without one, is another user, refused before the module while this one is held. Usernames compare
    /// ordinally (exact, case-sensitive). The username is never logged. As for <see cref="Login"/>, the login's own
    /// session is lent to <see cref="Pkcs11Login.OpenSession"/> on a token that allows one session at a time, and
    /// a login while a <see cref="OpenSession"/> session holds that only session fails with <c>CKR_SESSION_COUNT</c>.
    /// </remarks>
    /// <param name="user">Who logs in.</param>
    /// <param name="pin">The PIN. The caller keeps ownership of it.</param>
    /// <param name="username">The account name, sent UTF-8 encoded.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pin"/> or <paramref name="username"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">As for <see cref="Login"/>: a login is held already, the token is
    /// logged in outside the library, or the token refused the login.</exception>
    /// <exception cref="Pkcs11SessionException">As for <see cref="Login"/>: <c>CKR_SESSION_READ_ONLY_EXISTS</c>, or
    /// <c>CKR_SESSION_COUNT</c> when the login's own session could not open (no PIN is sent then).</exception>
    /// <exception cref="InvalidOperationException">As for <see cref="Login"/>.</exception>
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

    /// <summary>
    /// Takes a share of the login this application holds on the token for <paramref name="user"/>, without a PIN and
    /// without calling the module: for a component that should work under a login another part of the application
    /// made. Dispose the share once done; the login stays until its last holder goes.
    /// </summary>
    /// <remarks>
    /// Sharing is not authentication: it hands out what this application already has. A login made with a username
    /// (<see cref="LoginUser"/>) is shared through <see cref="TryShareLogin(TokenUser, string, out Pkcs11Login?)"/>.
    /// A login whose last holder has gone (its logout pending) is not shared.
    /// </remarks>
    /// <param name="user">Whose login to share.</param>
    /// <param name="login">The share, or <see langword="null"/> when no such login is held.</param>
    /// <returns>Whether a login was shared.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    public bool TryShareLogin(TokenUser user, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Pkcs11Login? login)
        => TryShareLoginCore(user, username: null, out login);

    /// <summary>
    /// Takes a share of the named login (<see cref="LoginUser"/>) this application holds on the token for
    /// <paramref name="user"/> and <paramref name="username"/>, without a PIN and without calling the module. See
    /// <see cref="TryShareLogin(TokenUser, out Pkcs11Login?)"/>.
    /// </summary>
    /// <param name="user">Whose login to share.</param>
    /// <param name="username">The account name the login was made with, compared ordinally.</param>
    /// <param name="login">The share, or <see langword="null"/> when no such login is held.</param>
    /// <returns>Whether a login was shared.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="username"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    public bool TryShareLogin(TokenUser user, string username,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Pkcs11Login? login)
    {
        ArgumentNullException.ThrowIfNull(username);
        if (username.Length == 0)
            throw new ArgumentException("Username must not be empty.", nameof(username));
        return TryShareLoginCore(user, username, out login);
    }

    private bool TryShareLoginCore(TokenUser user, string? username, out Pkcs11Login? login)
    {
        ThrowIfUndefined(user);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        LoginHold? hold = LoginRecord.TryShare(_library, user, username);
        login = hold is null ? null : new Pkcs11Login(this, user, username, hold);
        return login is not null;
    }

    private Pkcs11Login LoginCore(TokenUser user, SecurePin? pin, string? username)
    {
        ThrowIfUndefined(user);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Log.SlotTrace(_logger, (ulong)_slotId, username is null ? "Login" : "LoginUser");
        LoginHold hold = LoginRecord.Login(_library, user, pin, username);
        return new Pkcs11Login(this, user, username, hold);
    }

    // PKCS#11 v3.2 C_InitToken: CKR_SESSION_EXISTS while the application has a session open with the token. From
    // the sessions the library has open through any load of the module, a login's anchor among them (decision 6).
    private void ThrowIfSessionsExist()
    {
        (int readOnly, int readWrite) = TokenLoginRegistry.Of(_pkcs11Library.Module).Sessions(_slotId);
        if (readOnly + readWrite == 0)
            return;
        throw Pkcs11Exception.Create(CKR.CKR_SESSION_EXISTS, Pkcs11Operations.OpInitToken,
            $"{Pkcs11Operations.OpInitToken}: this application has {readOnly + readWrite} session(s) open on the token " +
            $"in slot {(ulong)_slotId} (a login keeps one of its own). Dispose every session and login on it first.");
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

        // PKCS#11 v3.2 C_OpenSession: CKR_SESSION_READ_WRITE_SO_EXISTS for a read-only session while the SO is
        // logged in. Known from the login record (decision 6); an SO login made outside the library is left to the module.
        if (!readWrite && LoginRecord.User == TokenUser.SecurityOfficer)
        {
            throw Pkcs11Exception.Create(CKR.CKR_SESSION_READ_WRITE_SO_EXISTS, Pkcs11Operations.OpOpenSession,
                $"{Pkcs11Operations.OpOpenSession}: the Security Officer is logged in to the token in slot {(ulong)_slotId} " +
                "through this application, and PKCS#11 allows no read-only session then. Open a read/write session, or " +
                "dispose the SO login first.");
        }

        ulong flags = CKF.CKF_SERIAL_SESSION;
        if (readWrite)
            flags |= CKF.CKF_RW_SESSION;

        CKR rv = _pkcs11Library.C_OpenSession(_slotId, (NativeCULong)flags, out NativeCULong sessionId);
        if (rv == CKR.CKR_SESSION_COUNT && !anchor && LoginRecord.IsLoggedIn)
        {
            // The module's answer, explained: the login's own session may be what uses up the token's sessions.
            throw Pkcs11Exception.Create(CKR.CKR_SESSION_COUNT, Pkcs11Operations.OpOpenSession,
                $"{Pkcs11Operations.OpOpenSession}: the token in slot {(ulong)_slotId} allows this application " +
                "no further session of the kind asked for (it may allow read/write ones no more, or any), and this " +
                "application's login on it keeps a session of its own. Open the session through that login " +
                "(Pkcs11Login.OpenSession), or dispose the login first.");
        }
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
