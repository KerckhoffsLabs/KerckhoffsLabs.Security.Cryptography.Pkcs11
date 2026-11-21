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
/// library. A slot from a lookup by its token (<see cref="Pkcs11Library.GetSlotByTokenLabel"/>,
/// <see cref="Pkcs11Library.GetSlotByUri(string)"/>, ...) re-checks that the slot still holds that token before a login
/// or <see cref="InitTokenWithPin"/>, so it is equal only to slots selected by the same token (label, serial number,
/// manufacturer and model as the lookup found them): never to one from <see cref="Pkcs11Library.GetSlotList"/>, which
/// does not check, so a set or dictionary of slots never trades one for the other. The hash code is the slot id's, so
/// such slots share a bucket.
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

    // The token a lookup selected this slot by (GetSlotByUri, GetSlotByTokenSerial, ...), or null: a login checks the
    // slot still holds it before sending the PIN. Read again after InitToken, which may relabel it.
    private volatile TokenInfo? _selectedToken;

    /// <summary>
    /// This slot, remembering <paramref name="token"/> as the one it was selected by: a login through it checks the
    /// slot still holds that token (label, serial number, manufacturer, model) before sending the PIN.
    /// </summary>
    internal Pkcs11Slot SelectedBy(TokenInfo token)
        => new(_library, (ulong)_slotId, _loggerFactory) { _selectedToken = token, _selectedBy = token };

    // The token the lookup found, as it found it: what equality compares (_selectedToken may be read again later).
    private TokenInfo? _selectedBy;

    /// <summary>The library this slot was listed by.</summary>
    internal Pkcs11Library Library => _library;

    /// <summary>
    /// Whether <paramref name="other"/> is the same slot of the same <see cref="Pkcs11Library"/>, selected the same way:
    /// both listed, or both looked up by the same token.
    /// </summary>
    /// <param name="other">The slot to compare with.</param>
    /// <returns><see langword="true"/> if both name the same slot id through the same library, selected the same way.</returns>
    public bool Equals(Pkcs11Slot? other)
        => other is not null && ReferenceEquals(_library, other._library) && _slotId == other._slotId
            && (_selectedBy, other._selectedBy) switch
            {
                (null, null) => true,
                ({ } mine, { } theirs) => TokenLoginRecord.IsSameToken(mine, theirs),
                _ => false,
            };

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
    /// Forgets the PINs the token in this slot refused, so that they may be sent to it again: for a token whose PIN was
    /// changed outside this library, to one it refused before.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Call it after changing a PIN with another tool. That covers a PIN changed back to an earlier one, and a rotation
    /// that put the new PIN in the secret store before the token was changed: a login tried in between sent the new
    /// PIN to a token that still had the old one, and that refusal stands until forgotten. Changing the token first,
    /// then the secret store, avoids it.
    /// </para>
    /// <para>
    /// A PIN the token refuses is never sent to it again for the same purpose: a login (<see cref="Login(TokenUser, LoginCredential, string?)"/>,
    /// <see cref="ShareOrLogin(LoginCredential, string?)"/> and their variants) of the same user and username, or a context login
    /// (<see cref="ContextAuthentication"/>), refused with <c>CKR_PIN_INCORRECT</c>, <c>CKR_PIN_INVALID</c> or
    /// <c>CKR_PIN_LEN_RANGE</c>; the old PIN of <see cref="Pkcs11Session.SetPinWithPin"/> for that user, or the Security
    /// Officer PIN of <see cref="InitTokenWithPin"/> (as for an SO login), refused with <c>CKR_PIN_INCORRECT</c> (the other
    /// two codes judge the new PIN there). The normal user's login PIN and the token's context PINs are one purpose for
    /// this: on most tokens they are the same PIN. The attempt is refused before the module with
    /// <see cref="Exceptions.Pkcs11AuthenticationException"/> (<c>CKR_PIN_INCORRECT</c>). Each wrong PIN costs one of the
    /// PIN's retries, so code that logs in once per request with a stale PIN from a secret store would otherwise lock the
    /// PIN within as many requests as it has retries. A different PIN is sent as usual. Sends are serialized per slot, so
    /// threads that send the same stale PIN at once cost it one retry, not one each. A token whose information cannot be
    /// read (<c>C_GetTokenInfo</c> failing) is not sent the PIN: it could be neither checked nor remembered.
    /// </para>
    /// <para>
    /// A context login's refusal holds for every key of the token, unless it is the PIN the user's login held was made
    /// with: it is then this key's refusal only (a key with a PIN of its own, such as a qualified signature key). Any
    /// other PIN refused for one key is taken for a stale one: a key's own PIN sent by mistake to another key, and, while
    /// the user's login was made on the pinpad (so its PIN is not known), the user's PIN sent to a key with a PIN of its
    /// own, which then blocks it for the user's login too.
    /// </para>
    /// <para>
    /// The library keeps no PIN for this, only an HMAC-SHA-256 of the refused one, under a random key held in memory;
    /// and, while a user login made with a PIN is held, of that PIN (dropped when the login ends). A refusal is forgotten
    /// when the PIN is accepted for the same purpose (a user login's PIN for the context logins too) or set as the PIN
    /// through this library (<see cref="Pkcs11Session.SetPinWithPin"/>, <see cref="Pkcs11Login.InitUserPinWithPin"/>);
    /// all of that user's (and, for the normal user, the context logins') when the PIN is set on the pinpad; all of them
    /// when the token is initialized, by this method, or once <see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/> has
    /// passed when it is set. Up to 64 are kept per slot: past that, the oldest is forgotten, which can cost one more
    /// retry. They are kept per module and slot (not per token: a module that renumbers its slots starts the new slot
    /// with none), for every <see cref="Pkcs11Library"/> loaded from the module, across its <c>C_Finalize</c> and a load
    /// from the same path, until the process ends.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    public void ForgetRefusedPins()
    {
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);
        LoginRecord.RefusedPins.ForgetAll();
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
    /// URI: <see cref="Pkcs11Library.GetSlotByUri(string)"/> then refuses rather than picks one. Each field is carried
    /// exactly but for its padding, an empty one as an empty value; a field no URI value can carry is refused rather
    /// than left out, which would name every token sharing the other fields. That refusal is about the data the token
    /// reports, not the call, so it is a <see cref="Pkcs11TokenException"/>.
    /// </remarks>
    /// <returns>The token's URI.</returns>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// <see cref="CKR.CKR_TOKEN_NOT_RECOGNIZED"/>: the module reported a field whose bytes are not UTF-8, or a serial
    /// number that is not printable ASCII once its trailing blanks and NULs (padding) are removed. No URI names the
    /// token; select it with <see cref="Pkcs11Library.GetSlot"/>.
    /// </exception>
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
    /// <exception cref="Pkcs11AuthenticationException">
    /// <c>CKR_PIN_INCORRECT</c>, synthesized: the token refused <paramref name="soPin"/> before as its Security Officer's
    /// PIN; it is not sent again (see <see cref="ForgetRefusedPins"/>). Or the module refused it.
    /// </exception>
    /// <exception cref="Pkcs11TokenException">
    /// <c>CKR_TOKEN_NOT_RECOGNIZED</c>: the slot was found by its token (a label, serial number or URI) and holds
    /// another one now; nothing is sent to it, and it is not erased.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying
    /// <c>C_GetTokenInfo</c> or <c>C_InitToken</c> call.</exception>
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

        // The SO PIN of a token initialized before is checked, at the cost of one of its retries when wrong: one the
        // token refused before is not sent again, and one it refuses now is remembered (as for an SO login), in one
        // step with every other PIN sent to the slot. The PIN goes to the native call straight out of the pinned buffer
        // SecurePin owns; no transient copy to zero.
        TokenLoginRecord record = LoginRecord;
        TokenLoginRecord.PinScope scope = record.PinScopeOf(
            RefusedPins.TokenIdentity(SelectedTokenNow(Pkcs11Operations.OpInitToken)), TokenUser.SecurityOfficer,
            username: null);
        TimeSpan? lifetime = _library.RefusedPinLifetime;
        CKR rv = record.RefusedPins.Serialized(() =>
        {
            if (record.RefusedPins.IsRefused(scope.Scope, soPin.Pin))
            {
                throw new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, Pkcs11Operations.OpInitToken,
                    $"{Pkcs11Operations.OpInitToken}: the token in slot {(ulong)_slotId} refused this Security Officer " +
                    "PIN before, so it was not sent again: each wrong PIN costs one of the PIN's retries, and repeating " +
                    "it would lock the PIN. Fix the PIN's source. If the token's SO PIN was changed outside this library, " +
                    "call ForgetRefusedPins().");
            }
            CKR answer = _pkcs11Library.C_InitToken(_slotId, soPin.Pin, tokenLabel);
            // CKR_PIN_INCORRECT: not the SO PIN of a token initialized before (a retry spent). CKR_PIN_INVALID and
            // CKR_PIN_LEN_RANGE refuse a new SO PIN's form, which spends none.
            if (answer == CKR.CKR_PIN_INCORRECT)
                record.RefusedPins.Refuse(scope.Purpose, scope.Identity, scope.Scope, soPin.Pin, lifetime);
            return answer;
        });
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpInitToken);
        Initialized();
    }

    // A token initialized afresh: its SO PIN is new, no user PIN is set yet, and its label may have changed. Every
    // refusal is forgotten, and a slot selected by its token takes the token as it is now, so a login through it (the
    // SO's, to set the user PIN) is not refused as made to another token.
    private void Initialized()
    {
        LoginRecord.RefusedPins.ForgetAll();
        if (_selectedToken is null)
            return;
        try
        {
            _selectedToken = GetTokenInfo();
        }
        catch (Pkcs11Exception)
        {
            // The token was initialized: that is not undone by failing to read it. The slot keeps the token it was
            // selected by, and a login through it says so if it no longer matches.
        }
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
    /// <exception cref="Pkcs11TokenException">
    /// <c>CKR_TOKEN_NOT_RECOGNIZED</c>: the slot was found by its token (a label, serial number or URI) and holds
    /// another one now; nothing is sent to it, and it is not erased.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The token has no protected authentication path (<see cref="TokenFlags.ProtectedAuthenticationPath"/>): refused
    /// before the module, which may take a call without a PIN as a wrong or an empty one.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetTokenInfo</c> (a token that cannot be read is not
    /// initialized) or <c>C_InitToken</c>.</exception>
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

        // Read before the call, so a token that cannot be read, one swapped in since a lookup selected the slot, or one
        // without a pinpad is not erased.
        TokenInfo now = SelectedTokenNow(Pkcs11Operations.OpInitToken);
        if (!now.TokenFlags.ProtectedAuthenticationPath)
            throw Pkcs11SessionCore.NoPinpad(Pkcs11Operations.OpInitToken, (ulong)_slotId);
        CKR rv = _pkcs11Library.C_InitToken(_slotId, default, tokenLabel);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpInitToken);
        Initialized();
    }

    // The token in the slot now, once found to be the one the slot was selected by, if it was (a lookup): initializing
    // erases the token, so a token swapped in since is neither sent the SO PIN nor erased.
    private TokenInfo SelectedTokenNow(string method)
    {
        TokenInfo now = GetTokenInfo();
        if (_selectedToken is { } selected && !TokenLoginRecord.IsSameToken(now, selected))
            throw TokenLoginRecord.AnotherToken((ulong)_slotId, method);
        return now;
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
    /// through it become invalid. Use <see cref="Pkcs11Login.OpenSession()"/> for a session that keeps the login.
    /// </para>
    /// <para>
    /// Disposing the session closes it and never logs out.
    /// </para>
    /// <para>
    /// A login keeps a session of its own, and on a token that allows this application one session at a time it
    /// <b>lends</b> that session to its own <see cref="Pkcs11Login.OpenSession()"/>. This method never lends: while a
    /// login holds the token's only session, a session opened here fails with <c>CKR_SESSION_COUNT</c> (use the login's
    /// <see cref="Pkcs11Login.OpenSession()"/> instead). A session opened here also holds that only session against a
    /// <see cref="Login(TokenUser, LoginCredential, string?)"/>, which fails with <c>CKR_SESSION_COUNT</c> until the session is disposed.
    /// </para>
    /// </remarks>
    /// <param name="access">
    /// <see cref="SessionAccess.ReadOnly"/>, the least privilege and the only kind a write-protected token accepts, or
    /// <see cref="SessionAccess.ReadWrite"/>, to create, change or destroy token objects. There is no default: a
    /// session that keeps a login (<see cref="Pkcs11Login.OpenSession()"/>) is read/write where the
    /// token allows it, and this one asks for what the caller says.
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
    /// login (<see cref="Pkcs11Login.OpenSession()"/>) instead, and the message says so.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// <c>CKR_TOKEN_WRITE_PROTECTED</c>: asked for <see cref="SessionAccess.ReadWrite"/>, the module opened a read-only
    /// session, which is closed: the session is of the access asked for, or none. A module that refuses the request answers
    /// this code itself; one may also open a read/write session on a write-protected token (NSS does), whose writes of
    /// token objects it then refuses.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c>.</exception>
    public Pkcs11Session OpenSession(SessionAccess access, ICryptoPolicy? policy = null)
    {
        ThrowIfUndefined(access);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Pkcs11SessionCore core = ExactAccess(OpenSessionCore(access == SessionAccess.ReadWrite, policy), access);
        return new Pkcs11Session(_library, this, core, access);
    }

    /// <summary>
    /// <paramref name="core"/>, opened for <paramref name="access"/>, once it is found to have it; else closed, and
    /// refused. A module may open a read-only session when asked for read/write, where it should refuse with
    /// <c>CKR_TOKEN_WRITE_PROTECTED</c>, and say so only in the session's flags: an access the caller named is exactly the
    /// one given, or none.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><c>CKR_TOKEN_WRITE_PROTECTED</c>: the module opened a read-only session.</exception>
    internal Pkcs11SessionCore ExactAccess(Pkcs11SessionCore core, SessionAccess access)
    {
        if (access != SessionAccess.ReadWrite || core.IsReadWrite)
            return core;
        core.Dispose();
        throw Pkcs11Exception.Create(CKR.CKR_TOKEN_WRITE_PROTECTED, Pkcs11Operations.OpOpenSession,
            $"{Pkcs11Operations.OpOpenSession}: asked for a read/write session, the module opened a read-only one on slot " +
            $"{(ulong)_slotId} (the token or slot allows no writes). Open a read-only session (SessionAccess.ReadOnly).");
    }

    /// <summary>
    /// Logs <paramref name="user"/> in to the token with <paramref name="credential"/>, and returns this caller's hold of
    /// the login.
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
    /// <see cref="Pkcs11Login"/> you were given, <see cref="TryShareLogin(out Pkcs11Login?)"/> for the
    /// normal user's login held on this slot, or <see cref="ShareOrLogin(LoginCredential, string?)"/>, which shares or logs in in
    /// one step. A login whose own session was lost (a token pulled and put back, an HSM failover), or that the module
    /// dropped, has ended: the refusal checks that session's state first (<c>C_GetSessionInfo</c>), and logs in afresh
    /// instead.
    /// </para>
    /// <para>
    /// When the token answers that a user is logged in already although this application holds no login, the login is
    /// either one the library left behind (its <c>C_Logout</c> failed, or its session was lost while others stayed
    /// open), which is logged out before the login is sent once more, so the PIN is checked; or a login made outside the
    /// library (another component calling the module directly), which is never taken over or logged out:
    /// <see cref="Pkcs11ForeignLoginException"/>.
    /// </para>
    /// <para>
    /// A slot found by a lookup (<see cref="Pkcs11Library.GetSlotByUri(string)"/>,
    /// <see cref="Pkcs11Library.GetSlotByTokenSerial"/>, ...) remembers the token it was selected by: the login checks
    /// the slot still holds that token (label, serial number, manufacturer, model) before the PIN is sent, so a token
    /// swapped in meanwhile does not receive it (<see cref="Pkcs11TokenException"/>, <c>CKR_TOKEN_NOT_RECOGNIZED</c>). A
    /// token reports its own identity: this does not tell a genuine token from one made to look like it.
    /// </para>
    /// <para>
    /// A logout waits for the operations in flight on the token (see <see cref="Pkcs11Login.Dispose"/>); a login while
    /// one is pending waits for it, then logs in afresh. A first login waits too for the operations in flight on the
    /// application's other sessions of the token (a search, a signature on a session from <see cref="OpenSession"/>):
    /// PKCS#11 asks that they finish before <c>C_Login</c>, and some modules end them when the login lands. It waits
    /// only for those in flight when it began, and does not stop others from starting; a login made from inside an
    /// operation (on this token or another) does not wait.
    /// </para>
    /// <para>
    /// The PIN is not kept: it is sent from the <see cref="SecurePin"/>'s buffer and never copied or logged. While a normal
    /// user's login is held, an HMAC-SHA-256 of its PIN is, under a random in-memory key (see <see cref="Pkcs11Login"/>).
    /// Fetch it from a secret store rather than code or configuration. A PIN the token refuses is not sent to it again for the
    /// same user: a second attempt with it is refused before the module (<c>CKR_PIN_INCORRECT</c>), so a stale PIN
    /// costs one of the PIN's retries, however often it is tried. See <see cref="ForgetRefusedPins"/>.
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
    /// <see cref="Pkcs11Login.OpenSession()"/>, one working session at a time, so a login does not need a second session
    /// to work with. While it holds the token's only session, <see cref="OpenSession"/> fails with
    /// <c>CKR_SESSION_COUNT</c>: open the session through the login instead.
    /// </para>
    /// <para>
    /// With a <paramref name="username"/>, the login is <c>C_LoginUser</c> (PKCS#11 v3.0), for tokens with user accounts.
    /// The username is part of who is logged in: a login under another username, or one without, is another user,
    /// refused before the module while this one is held. Usernames compare ordinally (exact, case-sensitive), and are
    /// never logged.
    /// </para>
    /// <para>
    /// <see cref="LoginCredential.Pinpad"/> logs in through the token's protected authentication path; a token without
    /// one (<see cref="TokenFlags.ProtectedAuthenticationPath"/>) is refused before the module. With
    /// <see cref="LoginCredential.FromPinSource(Func{SecurePin})"/>, the source runs once, before the login, and its PIN is
    /// disposed once done with.
    /// </para>
    /// </remarks>
    /// <param name="user">Who logs in: <see cref="TokenUser.User"/>, or <see cref="TokenUser.SecurityOfficer"/>.</param>
    /// <param name="credential">The PIN (a <see cref="SecurePin"/> converts implicitly; the caller keeps ownership), a PIN
    /// source, or <see cref="LoginCredential.Pinpad"/>.</param>
    /// <param name="username">The account name for <c>C_LoginUser</c>, sent UTF-8 encoded; <see langword="null"/> (the
    /// default) for <c>C_Login</c>.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="credential"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="user"/> is not a defined value.</exception>
    /// <exception cref="ObjectDisposedException">The library, or the credential's PIN, is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">This application holds a login on the token already
    /// (<c>CKR_USER_ALREADY_LOGGED_IN</c> or <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>, refused before the module); the
    /// token refused this PIN for this user before (<c>CKR_PIN_INCORRECT</c>, refused before the module: a refused PIN
    /// is never sent again, see <see cref="ForgetRefusedPins"/>); or the token refused the login.</exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside the library.</exception>
    /// <exception cref="Pkcs11TokenException">The slot no longer holds the token it was selected by
    /// (<c>CKR_TOKEN_NOT_RECOGNIZED</c>); no PIN is sent.</exception>
    /// <exception cref="Pkcs11SessionException">A Security Officer login while this application has a read-only
    /// session open on the token (<c>CKR_SESSION_READ_ONLY_EXISTS</c>, refused before the module); or the login's
    /// own session could not open because the token allows this application no more sessions
    /// (<c>CKR_SESSION_COUNT</c>, from the module; no PIN is sent).</exception>
    /// <exception cref="InvalidOperationException">Called from inside an operation on the token while the previous
    /// login's logout waits for operations to finish; or from code the library called while logging in to this token (a
    /// logger), which cannot log in to it; or <see cref="LoginCredential.Pinpad"/> on a token with no protected
    /// authentication path; or a PIN source returned <see langword="null"/> or a disposed PIN.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetTokenInfo</c> (the token is read before the PIN is sent, and a token that cannot be read
    /// is not sent it: <c>CKR_TOKEN_NOT_PRESENT</c> or <c>CKR_DEVICE_REMOVED</c> once removed), <c>C_OpenSession</c>,
    /// <c>C_Login</c> or <c>C_LoginUser</c> (<c>CKR_FUNCTION_NOT_SUPPORTED</c> from a module before v3.0).</exception>
    public Pkcs11Login Login(TokenUser user, LoginCredential credential, string? username = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (username is not null)
            ThrowIfNullOrEmpty(username);
        if (credential is not LoginCredential.PinSource source)
            return LoginCore(user, credential is LoginCredential.FixedPin fixedPin ? fixedPin.Pin : null, username);

        // Read before the login, outside every lock (it may prompt, or wait for another thread), and disposed once
        // done with, sent or not.
        using SecurePin pin = TokenLoginRecord.TakePin(source.Source);
        return LoginCore(user, pin, username);
    }

    private static void ThrowIfNullOrEmpty(string username, [CallerArgumentExpression(nameof(username))] string? name = null)
    {
        ArgumentNullException.ThrowIfNull(username, name);
        if (username.Length == 0)
            throw new ArgumentException("Username must not be empty.", name);
    }

    /// <summary>
    /// Takes a share of the normal user's login this application holds on the token, without a PIN: for a component
    /// that should work under a login another part of the application made. Dispose the share once done; the login
    /// stays until its last holder goes.
    /// </summary>
    /// <remarks>
    /// Sharing is not authentication: it hands out what this application already has. A login made with a username
    /// (<see cref="Login(TokenUser, LoginCredential, string?)"/>) is shared through <see cref="TryShareLogin(string, out Pkcs11Login?)"/>. A login whose
    /// last holder has gone (its logout pending) is not shared. Only the normal user's login is shared from the slot: a
    /// Security Officer login, which can set the user's PIN, is shared only by handing its <see cref="Pkcs11Login"/> on
    /// (<see cref="Pkcs11Login.Share"/>). To share or log in in one step, use <see cref="ShareOrLogin(LoginCredential, string?)"/>.
    /// The module is not called, except on a slot found by a lookup, whose token is checked as for <see cref="Login(TokenUser, LoginCredential, string?)"/>.
    /// </remarks>
    /// <param name="login">The share, or <see langword="null"/> when no such login is held.</param>
    /// <returns>Whether a login was shared.</returns>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11TokenException">A login of this user is held, and the slot no longer holds the token it
    /// was selected by (<c>CKR_TOKEN_NOT_RECOGNIZED</c>), or reading it failed (<c>CKR_TOKEN_NOT_PRESENT</c>,
    /// <c>CKR_DEVICE_REMOVED</c>).</exception>
    public bool TryShareLogin([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Pkcs11Login? login)
        => TryShareLoginCore(username: null, out login);

    /// <summary>
    /// Takes a share of the named normal user's login (<see cref="Login(TokenUser, LoginCredential, string?)"/>) this application holds on the token for
    /// <paramref name="username"/>, without a PIN. See <see cref="TryShareLogin(out Pkcs11Login?)"/>.
    /// </summary>
    /// <param name="username">The account name the login was made with, compared ordinally.</param>
    /// <param name="login">The share, or <see langword="null"/> when no such login is held.</param>
    /// <returns>Whether a login was shared.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="username"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11TokenException">As for <see cref="TryShareLogin(out Pkcs11Login?)"/>.</exception>
    public bool TryShareLogin(string username, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Pkcs11Login? login)
    {
        ThrowIfNullOrEmpty(username);
        return TryShareLoginCore(username, out login);
    }

    // The normal user's only: sharing the SO login from the slot would hand any code in the process C_InitPIN, with no
    // PIN, so it is shared only through Pkcs11Login.Share.
    private bool TryShareLoginCore(string? username, out Pkcs11Login? login)
    {
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        LoginHold? hold = LoginRecord.TryShare(_library, TokenUser.User, username, _selectedToken);
        login = hold is null ? null : new Pkcs11Login(this, TokenUser.User, username, hold);
        return login is not null;
    }

    private Pkcs11Login LoginCore(TokenUser user, SecurePin? pin, string? username)
    {
        ThrowIfUndefined(user);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Log.SlotTrace(_logger, (ulong)_slotId, username is null ? "Login" : "LoginUser");
        LoginHold hold = LoginRecord.Login(_library, user, pin, username, _selectedToken);
        return new Pkcs11Login(this, user, username, hold);
    }

    /// <summary>
    /// Shares the normal user's login this application holds on the token, or logs the normal user in when none is
    /// held, in one step: for components that each need the login and must not race into a refusal. The PIN is fetched
    /// from <paramref name="credential"/> only when no login is held to share.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A share checks no PIN: PKCS#11 cannot check one against a login already made. So the PIN is used only when this
    /// call makes the login; a component that must prove it knows the PIN cannot do so here, or anywhere while the
    /// login is held. For the normal user only: a Security Officer login is shared only by handing its
    /// <see cref="Pkcs11Login"/> on (<see cref="Pkcs11Login.Share"/>).
    /// </para>
    /// <para>
    /// A logout pending or in flight is waited for, then the login made afresh. A login of another user is refused
    /// (<c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>); a login made outside the library is refused with
    /// <see cref="Pkcs11ForeignLoginException"/>, never taken over. On a slot found by a lookup, a login held is shared
    /// only while the slot holds the token it was selected by (<c>CKR_TOKEN_NOT_RECOGNIZED</c> otherwise).
    /// </para>
    /// <para>
    /// A PIN source (<see cref="LoginCredential.FromPinSource(Func{SecurePin})"/>) runs when no login is held to share,
    /// before the login is made: nothing waits for it, and it may take its time, or wait for other threads, which may log
    /// in to this token meanwhile. A login made in the meantime (another component's, or one it made itself) is then
    /// shared, and the PIN disposed unsent. Prefer it when reading the PIN has a cost (a secret store, a prompt). A PIN
    /// the caller keeps (a <see cref="SecurePin"/>, which converts implicitly) is never disposed, and is sent only when no
    /// login is held to share; <see cref="LoginCredential.Pinpad"/> is used only then too.
    /// </para>
    /// <para>
    /// With a <paramref name="username"/>, the login shared or made is that named user's (<c>C_LoginUser</c>), compared
    /// ordinally with the login held.
    /// </para>
    /// </remarks>
    /// <param name="credential">The PIN (a <see cref="SecurePin"/> converts implicitly), a PIN source, or
    /// <see cref="LoginCredential.Pinpad"/>; used only when no login is held to share.</param>
    /// <param name="username">The account name for <c>C_LoginUser</c>, sent UTF-8 encoded; <see langword="null"/> (the
    /// default) for <c>C_Login</c>.</param>
    /// <returns>The caller's hold of the login; dispose it once done.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="credential"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="ObjectDisposedException">The library is disposed.</exception>
    /// <exception cref="Pkcs11AuthenticationException">Another user is logged in; the token refused this PIN before
    /// (<c>CKR_PIN_INCORRECT</c>, not sent again, see <see cref="ForgetRefusedPins"/>); or the token refused the
    /// login.</exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside the library.</exception>
    /// <exception cref="Pkcs11TokenException">The slot no longer holds the token it was selected by
    /// (<c>CKR_TOKEN_NOT_RECOGNIZED</c>); no PIN is sent, and the source is not called.</exception>
    /// <exception cref="InvalidOperationException">A PIN source returned <see langword="null"/> or a disposed
    /// <see cref="SecurePin"/>; or <see cref="LoginCredential.Pinpad"/>, with no login held to share, on a token with no
    /// protected authentication path; or called
    /// from inside an operation while the previous login's logout waits for operations to finish; or from code the library called while logging in to this token (a
    /// logger), which cannot log in to it.</exception>
    /// <exception cref="Pkcs11Exception">As for <see cref="Login(TokenUser, LoginCredential, string?)"/>.</exception>
    public Pkcs11Login ShareOrLogin(LoginCredential credential, string? username = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (username is not null)
            ThrowIfNullOrEmpty(username);
        ObjectDisposedException.ThrowIf(_library.IsDisposed, _library);

        Log.SlotTrace(_logger, (ulong)_slotId, "ShareOrLogin");
        LoginHold hold = credential switch
        {
            LoginCredential.FixedPin fixedPin
                => LoginRecord.ShareOrLogin(_library, TokenUser.User, username, _selectedToken, fixedPin.Pin),
            LoginCredential.PinSource source
                => LoginRecord.ShareOrLogin(_library, TokenUser.User, username, _selectedToken, source.Source),
            _ => LoginRecord.ShareOrLogin(_library, TokenUser.User, username, _selectedToken, pinSource: null),
        };
        return new Pkcs11Login(this, TokenUser.User, username, hold);
    }

    // PKCS#11 v3.2 C_InitToken: CKR_SESSION_EXISTS while the application has a session open with the token. From
    // the sessions the library has open through any load of the module, a login's anchor among them.
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
        // logged in. Known from the login record; an SO login made outside the library is left to the module.
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

        // A module may open a read-only session when asked for read/write, and say so only in its flags: the access
        // recorded is the one granted, so the library's refusals for read-only sessions and Pkcs11Session.Access hold. A
        // module that cannot answer is taken at its word.
        if (readWrite && _pkcs11Library.C_GetSessionInfo(sessionId, out CK_SESSION_INFO info) == CKR.CKR_OK
            && ((ulong)info.Flags & CKF.CKF_RW_SESSION) == 0)
        {
            readWrite = false;
        }

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
