using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// Logging in: the checks before a PIN is sent, the login's own session, the send, and the PIN scopes of refused PINs.
internal sealed partial class TokenLoginRecord
{
    /// <summary>
    /// Logs <paramref name="user"/> in, and returns the caller's share of the login. Refuses a login while one is held
    /// (see the class remarks): the same user's with <c>CKR_USER_ALREADY_LOGGED_IN</c>, anyone else's with
    /// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>, both before the module and with no PIN sent.
    /// </summary>
    /// <param name="owner">The library the share comes through; its <c>Dispose</c> releases it.</param>
    /// <param name="user">Who logs in.</param>
    /// <param name="pin">The PIN, or <see langword="null"/> for the protected authentication path (a pinpad).</param>
    /// <param name="username">The username for <c>C_LoginUser</c>, or <see langword="null"/> for <c>C_Login</c>.</param>
    /// <param name="expectedToken">
    /// The token the caller selected the slot by, or <see langword="null"/>: checked against the slot's token after the
    /// login's session opens and before the PIN is sent, so a token swapped in meanwhile does not receive it.
    /// </param>
    /// <exception cref="Pkcs11AuthenticationException">
    /// A login is held through this record (<c>CKR_USER_ALREADY_LOGGED_IN</c> for the same user,
    /// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c> for another; refused before the module); or the module refused the
    /// login.
    /// </exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside this library.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// The token in the slot is not <paramref name="expectedToken"/> (<c>CKR_TOKEN_NOT_RECOGNIZED</c>); no PIN is sent.
    /// </exception>
    /// <exception cref="Pkcs11SessionException">
    /// An SO login while the library has a read-only session open on the slot (<c>CKR_SESSION_READ_ONLY_EXISTS</c>,
    /// refused before the module); or the anchor could not open because the token allows the application no more
    /// sessions (<c>CKR_SESSION_COUNT</c> from <c>C_OpenSession</c>, with a message giving the library's session tally
    /// on the slot). No <c>C_Login</c> is sent then.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Called from inside an operation on the token while the previous login's logout waits for operations to finish.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_OpenSession</c> or the login.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is disposed, or its disposal began before the hold was taken.</exception>
    public LoginHold Login(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username,
        TokenInfo? expectedToken = null)
        => LoginCore(owner, user, username, expectedToken, shareHeld: false, () => pin);

    /// <summary>
    /// Shares the login held for <paramref name="user"/> (and <paramref name="username"/>), or logs in when none is
    /// held, deciding under the transition semaphore, so two callers never race into a refusal: for
    /// <see cref="Pkcs11Slot.ShareOrLogin(LoginCredential, string?)"/>. <paramref name="pinSource"/> runs when no login is held
    /// to share, outside the semaphore (it may take its time, or wait for a thread that logs in to the token); a login
    /// made meanwhile is then shared. The PIN it returns is disposed, sent or not. A share checks no PIN.
    /// </summary>
    /// <param name="owner">The library the share comes through.</param>
    /// <param name="user">Whose login to share or make.</param>
    /// <param name="username">The username for <c>C_LoginUser</c>, or <see langword="null"/>.</param>
    /// <param name="expectedToken">The token the slot was selected by, or <see langword="null"/> (see <see cref="Login"/>).</param>
    /// <param name="pinSource">The PIN's source, or <see langword="null"/> for the protected authentication path.</param>
    /// <exception cref="Pkcs11AuthenticationException">Another user is logged in, or the module refused the login.</exception>
    /// <exception cref="Pkcs11ForeignLoginException">The token is logged in outside this library.</exception>
    public LoginHold ShareOrLogin(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        Func<SecurePin>? pinSource)
        => LoginCore(owner, user, username, expectedToken, shareHeld: true, () => pinSource is null ? null : TakePin(pinSource));

    /// <summary>
    /// As <see cref="ShareOrLogin(Pkcs11Library, TokenUser, string?, TokenInfo?, Func{SecurePin}?)"/>, with a PIN the
    /// caller keeps: never disposed here.
    /// </summary>
    public LoginHold ShareOrLogin(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        SecurePin pin)
        => LoginCore(owner, user, username, expectedToken, shareHeld: true, () => pin, disposeFetched: false);

    internal static SecurePin TakePin(Func<SecurePin> pinSource)
    {
        SecurePin pin = pinSource() ?? throw new InvalidOperationException("The PIN source returned null.");
        if (pin.IsDisposed)
        {
            throw new InvalidOperationException(
                "The PIN source returned a disposed SecurePin. The library disposes the PIN it is given once it is done " +
                "with it: return a new SecurePin from the source every time, never one you keep.");
        }
        return pin;
    }

    // The function a login calls: C_LoginUser for a named user, else C_Login. Refuses an empty username.
    private static string LoginMethodOf(string? username)
    {
        if (username is { Length: 0 })
            throw new ArgumentException("Username must not be empty.", nameof(username));
        return username is null ? OpLogin : OpLoginUser;
    }

    // A share's PIN, from its source: handed to owner, which disposes it on the way out, unless disposeFetched is false.
    private static SecurePin? FetchSharePin(Func<SecurePin?> pin, Owned<SecurePin> owner, bool disposeFetched)
    {
        SecurePin? fetched = pin();
        if (fetched is not null && disposeFetched)
            owner.Own(fetched);
        return fetched;
    }

    // The PIN a first login sends: a share's, fetched from its source outside the semaphore; a login's, its caller's.
    private static SecurePin? PinToSend(bool shareHeld, SecurePin? fetched, Func<SecurePin?> pin)
        => shareHeld ? fetched : pin();

    private LoginHold LoginCore(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken,
        bool shareHeld, Func<SecurePin?> pin, bool disposeFetched = true)
    {
        ArgumentNullException.ThrowIfNull(owner);
        string method = LoginMethodOf(username);

        // Both made before anything changes: they run the caller's logger factory, and a throw then leaves nothing
        // half done.
        ILoggerFactory? loggerFactory = owner.LoggerFactory;
        ILogger logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<TokenLoginRecord>();

        // The operations a first login waits for: those in flight when it first found it had to log in (null when none
        // was, or once they ended).
        int? operationsBefore = null;
        bool waitedForOperations = false;
        // A share's PIN comes from the caller's source, run outside the semaphore (it may take its time, or wait for a
        // thread that logs in to this token), once a first look found no login to share; owned, and disposed on the way
        // out, sent or not (unless disposeFetched is false). A login's is the caller's, at hand.
        SecurePin? fetched = null;
        using var ownedFetched = new Owned<SecurePin>();
        bool pinAtHand = !shareHeld;
        bool fetchPin = false;
        while (true)
        {
            // Before any wait: a logout handed to this thread would wait for it to release the semaphore.
            ThrowIfHoldingTransition();
            if (operationsBefore is { } epoch)
            {
                WaitForOperationsBefore(epoch);
                operationsBefore = null;
                waitedForOperations = true;
            }
            if (fetchPin)
            {
                fetchPin = false;
                fetched = FetchSharePin(pin, ownedFetched, disposeFetched);
                pinAtHand = true;
            }
            WaitForNoLogoutUnderway();
            WaitForAnchorClosed();
            AcquireTransition();
            try
            {
                switch (HeldLogin(owner, user, username, method, shareHeld, expectedToken, out LoginHold? shared))
                {
                    case Held.Shared:
                        return shared!;
                    case Held.LogoutUnderway:
                        continue;
                    default:
                        break;
                }

                // The share's PIN, fetched now the semaphore is let go: a login made meanwhile is then shared, and the
                // PIN disposed unsent. Before the operations in flight are looked at, so a slow source (a prompt) is not
                // followed by a login that lands inside operations started while it ran.
                if (!pinAtHand)
                {
                    // Not for a token swapped in since the slot was selected: the source (a prompt) is not run for it.
                    ThrowIfAnotherToken(owner, expectedToken, method);
                    fetchPin = true;
                    continue;
                }

                // PKCS#11 (C_Login): operations active when a login lands may or may not stay active, so they should
                // finish first. Those in flight on the token's other sessions are waited for, once, outside the
                // semaphore (an operation may need it on its way out); those that start meanwhile are not, so the wait
                // ends. A login from inside an operation (on any token) does not wait: on this token its own operation
                // is active, and on another, two such logins would wait for each other.
                if (!waitedForOperations && t_operationsOnThread == 0 && StartOperationEpoch() is { } inFlight)
                {
                    operationsBefore = inFlight;
                    continue;
                }

                return FirstLogin(owner, user, PinToSend(shareHeld, fetched, pin), username, loggerFactory, logger, expectedToken);
            }
            finally
            {
                ReleaseTransition();
            }
        }
    }

    // The scope of a token login's PIN (RefusedPins): the token in the slot, the user, the username; and the token's
    // identity. A token that cannot be read is not sent the PIN: it could not be checked against the token's refusals,
    // nor a refusal remembered (Pkcs11Exception from C_GetTokenInfo).
    private PinScope LoginPinScope(Pkcs11Library owner, TokenUser user, string? username)
        => PinScopeOf(RefusedPins.TokenIdentity(new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory: null).GetTokenInfo()),
            user, username);

    // The scope of the PIN of user (and username) on the token identity names.
    internal PinScope PinScopeOf(string identity, TokenUser user, string? username)
    {
        RefusedPins.Purposes purpose = user == TokenUser.SecurityOfficer
            ? RefusedPins.Purposes.SecurityOfficer
            : RefusedPins.Purposes.User;
        byte[] name = username is null ? [] : System.Text.Encoding.UTF8.GetBytes(username);
        try
        {
            return new PinScope(purpose, identity, RefusedPins.Scope(purpose, identity, name));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(name);
        }
    }

    /// <summary>
    /// The scope of the PIN <c>C_SetPIN</c> changes on the token <paramref name="identity"/> names: the PIN of the user
    /// this record holds logged in (and its username), or the normal user's when none is (PKCS#11 C_SetPIN).
    /// </summary>
    internal PinScope SetPinScope(string identity)
    {
        TokenUser? user;
        string? username;
        lock (_lock)
        {
            user = _user;
            username = _username;
        }
        return PinScopeOf(identity, user ?? TokenUser.User, user is null ? null : username);
    }

    /// <summary>
    /// What a PIN is for (<see cref="RefusedPins"/>): its purpose and scope, on the token identity names.
    /// </summary>
    internal readonly record struct PinScope(RefusedPins.Purposes Purpose, string Identity, byte[] Scope);

    /// <summary>
    /// After <c>C_SetPIN</c> changed the user's PIN to <paramref name="pin"/>, under <see cref="RefusedPins.Serialized"/>:
    /// the PIN remembered for the user's login held, or being made, is the new one, or none when no user login is. Decided under the
    /// record's lock, so a logout that lands meanwhile cannot leave a PIN remembered with no login.
    /// </summary>
    internal void ReplaceUserPin(string identity, ReadOnlySpan<byte> pin)
    {
        lock (_lock)
        {
            // A first login being made remembered its PIN already, before the login is recorded: replaced too.
            bool remember = (_anchor is not null && _user == TokenUser.User) || RefusedPins.RemembersUserPin;
            RefusedPins.ForgetUserPin();
            if (remember)
                RefusedPins.RememberUserPin(identity, pin);
        }
    }

    private Pkcs11AuthenticationException RefusedBefore(string method, TokenUser user, string? username)
        => new(CKR.CKR_PIN_INCORRECT, method,
            $"{method}: the token in slot {(ulong)_slotId} refused this PIN before, for this " +
            $"{Describe(user, username)}, so it was not sent again: each wrong PIN costs one of the PIN's retries, " +
            "and repeating it would lock the PIN. Fix the PIN's source. If the token's PIN was changed outside this " +
            "library (to this PIN, or after it was put in the secret store), call Pkcs11Slot.ForgetRefusedPins().");

    private enum Held { None, Shared, LogoutUnderway }

    private Held NoneUnlessLogoutUnderway()
    {
        lock (_lock)
            return _pendingLogout is not null || _logoutInFlight ? Held.LogoutUnderway : Held.None;
    }

    // A login held by another user, or under another username, is refused: a token holds one login at a time.
    private void ThrowIfAnotherUser(TokenUser heldUser, string? heldUsername, TokenUser user, string? username, string method)
    {
        if (heldUser == user && string.Equals(heldUsername, username, StringComparison.Ordinal))
            return;

        // The usernames stay out of the message: it is commonly logged.
        throw new Pkcs11AuthenticationException(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, method,
            $"{method}: the token in slot {(ulong)_slotId} already has a {Describe(heldUser, heldUsername)} logged in " +
            "through this application, and a token holds one login at a time. Dispose every login and session that " +
            "holds it before logging in as someone else.");
    }

    // Under the transition semaphore. With a login held, once a probe of its anchor finds it still holding: refuses
    // another user (CKR_USER_ANOTHER_ALREADY_LOGGED_IN); for the same user, shares it (shareHeld, once the slot is found
    // to hold expectedToken still) or refuses (CKR_USER_ALREADY_LOGGED_IN). LogoutUnderway when a logout is pending or in
    // flight (the caller waits and looks again); None when no login is held, the probe included.
    private Held HeldLogin(Pkcs11Library owner, TokenUser user, string? username, string method, bool shareHeld,
        TokenInfo? expectedToken, out LoginHold? shared)
    {
        shared = null;
        Pkcs11SessionCore? anchor;
        TokenUser? heldUser;
        string? heldUsername;
        long generation;
        lock (_lock)
        {
            if (_pendingLogout is not null || _logoutInFlight)
                return Held.LogoutUnderway;
            anchor = _anchor;
            heldUser = _user;
            heldUsername = _username;
            generation = _generation;
        }

        if (anchor is null || heldUser is not { } held)
            return Held.None;

        // A lost anchor (a token pulled and put back, an HSM failover), or a module that dropped the login while the
        // anchor stayed open, ended the login: the probe reports it, the login ends, and this call logs in afresh, for
        // whichever user it asks for. Probed before the users are compared, so a login that is gone never refuses
        // another user's.
        if (!AnchorStillHolds(anchor, generation, held))
            return NoneUnlessLogoutUnderway();

        ThrowIfAnotherUser(held, heldUsername, user, username, method);

        if (shareHeld)
        {
            // A slot selected by its token shares a login only while it holds that token: a token swapped in since,
            // and logged in by another component, is not the one the caller asked for.
            ThrowIfAnotherToken(owner, expectedToken, method);
            lock (_lock)
            {
                if (_anchor is not null && _generation == generation && _holders.Count > 0 && !_ending)
                {
                    shared = AddHolderLocked(owner);
                    return Held.Shared;
                }
            }
            return NoneUnlessLogoutUnderway();
        }

        throw new Pkcs11AuthenticationException(CKR.CKR_USER_ALREADY_LOGGED_IN, method,
            $"{method}: the token in slot {(ulong)_slotId} already has this {Describe(user, username)} logged in through " +
            "this application, so the PIN was not sent: PKCS#11 cannot check a PIN against a login already made. Use " +
            "that login: Pkcs11Slot.ShareOrLogin, Pkcs11Login.Share() on a Pkcs11Login you were given, or " +
            "Pkcs11Slot.TryShareLogin for the login held on the slot; or dispose every login and session that holds it, " +
            "then log in again.");
    }

    // Whether the anchor of the login of generation still holds it: C_GetSessionInfo on it. A loss code ends the login
    // (Pkcs11SessionCore.ThrowIfError, then AnchorLost); a state other than the logged-in user's means the module
    // dropped the login, which ends it too (and leaves nothing on the token). A busy anchor (lent, in an operation) is
    // in use, so it holds. Any other failure is not evidence that the login ended.
    private bool AnchorStillHolds(Pkcs11SessionCore anchor, long generation, TokenUser user)
    {
        CKS? state;
        try
        {
            state = anchor.TrySendProbe();
        }
        catch (Exception ex) when (ex is Pkcs11Exception or ObjectDisposedException)
        {
            // A failure is no evidence, unless the anchor is known lost: then the login went with it, even if its loss
            // was seen before the login was recorded, when ending it was not this record's to do (AnchorLost).
            if (anchor.LostTo is var lost and not CKR.CKR_OK)
                EndLogin(lost, anchor);
            return IsCurrent(generation);
        }

        if (state is { } reported && TryUserOf(reported, out TokenUser? reportedUser) && reportedUser != user)
            EndLogin(CKR.CKR_USER_NOT_LOGGED_IN, anchor, moduleLoggedOut: true);
        return IsCurrent(generation);
    }

    // The user a session's state shows logged in, or null for a public session. False for a state PKCS#11 does not
    // define, which is no evidence either way: the caller acts as when the probe could not be answered.
    private static bool TryUserOf(CKS state, out TokenUser? user)
    {
        switch (state)
        {
            case CKS.CKS_RW_SO_FUNCTIONS:
                user = TokenUser.SecurityOfficer;
                return true;
            case CKS.CKS_RO_USER_FUNCTIONS or CKS.CKS_RW_USER_FUNCTIONS:
                user = TokenUser.User;
                return true;
            case CKS.CKS_RO_PUBLIC_SESSION or CKS.CKS_RW_PUBLIC_SESSION:
                user = null;
                return true;
            default:
                user = null;
                return false;
        }
    }

    // Under the transition semaphore, with no login held: opens the anchor, checks the token is the one selected, sends
    // the login on it, and records it.
    private LoginHold FirstLogin(Pkcs11Library owner, TokenUser user, SecurePin? pin, string? username,
        ILoggerFactory? loggerFactory, ILogger logger, TokenInfo? expectedToken)
    {
        string method = username is null ? OpLogin : OpLoginUser;
        ThrowIfReadOnlySessionBlocksSo(user, method);

        // Closed on every way out of this scope but one: the record keeps it once the login is recorded. Closing
        // the only session this record opened also leaves the token public again.
        using var anchor = new Owned<Pkcs11SessionCore>(OpenAnchor(owner, user, loggerFactory));
        ThrowIfAnotherToken(owner, expectedToken, method);

        // A PIN the token refused before for this login is not sent again, and one it refuses now is remembered
        // (RefusedPins), in one step with every other PIN sent to the slot. The token is read after the re-check above,
        // so a refusal is scoped to the token the PIN goes to. The pinpad has no PIN to remember: each one is typed
        // afresh.
        PinScope? scope = pin is null ? null : LoginPinScope(owner, user, username);
        if (scope is { } checkedScope)
        {
            Pkcs11SessionCore session = anchor.Value;
            TimeSpan? lifetime = owner.RefusedPinLifetime;
            // A PIN its caller keeps may be disposed meanwhile: zeroed only once checked, sent and recorded.
            using SecurePin.Use use = pin!.BeginUse();
            RefusedPins.Serialized(() => SendFirstLoginOnce(session, user, pin, username, method, checkedScope, lifetime));
        }
        else
        {
            // No PIN: the pinpad, which only a token with a protected authentication path has.
            anchor.Value.ThrowIfNoPinpadForRecord(method);
            SendFirstLogin(anchor.Value, user, pin, username, method);
        }

        // From here the module holds the login, and nothing else has seen it: any way out but recording it logs it back
        // out first. A login the module answered CKR_OK to but does not report, or a logger that threw on the way,
        // would otherwise stay on the token unrecorded, and the next login would take it for a foreign one.
        try
        {
            ThrowIfNotLoggedIn(anchor.Value, user, method);
        }
        catch
        {
            RefusedPins.ForgetUserPin();
            LogBackOut(anchor.Value, user, owner);
            throw;
        }

        lock (_lock)
        {
            // The owner's disposal began while the login was sent: its holds may already be released, so a
            // hold taken now would never be. Checked before the login is recorded, and undone below.
            if (!owner.IsDisposingOrDisposed)
            {
                _anchor = anchor.Release();
                _user = user;
                _username = username;
                _generation++;
                _logger = logger;
                _ending = false;
                _leftBehind = null;
                _loginOwner = owner;
                _loginEnded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                // Not checked again: a disposal that began since is to release this hold, and a throw here would leave
                // the login just recorded with no holder to log it out.
                return NewHolderLocked(owner);
            }
        }

        RefusedPins.ForgetUserPin();
        LogBackOut(anchor.Value, user, owner);
        throw OwnerDisposed();
    }

    // One step of RefusedPins, with every other PIN sent to the slot: a PIN refused before for this login is not sent
    // again, one the token refuses now is remembered, and one it takes is forgotten as refused and, for the user,
    // remembered as the user's.
    private void SendFirstLoginOnce(Pkcs11SessionCore session, TokenUser user, SecurePin pin, string? username,
        string method, PinScope checkedScope, TimeSpan? lifetime)
    {
        // The normal user's PIN is usually the context PIN too: one refused as a stale context PIN is not tried
        // as the user's either, so a stale secret costs one retry in all, not one per use.
        bool refused = RefusedPins.IsRefused(checkedScope.Scope, pin.Pin);
        bool refusedAsContext = user == TokenUser.User
            && RefusedPins.IsRefused(RefusedPins.ContextScope(checkedScope.Identity), pin.Pin);
        if (refused || refusedAsContext)
            throw RefusedBefore(method, user, username);
        try
        {
            SendFirstLogin(session, user, pin, username, method);
        }
        catch (Pkcs11Exception ex) when (RefusedPins.IsPinRefusal(ex.ReturnValue))
        {
            RefusedPins.Refuse(checkedScope.Purpose, checkedScope.Identity, checkedScope.Scope, pin.Pin, lifetime);
            throw;
        }
        // The PIN is the token's: a refusal of it for this login, kept from before it was changed outside the
        // library, is forgotten (the others stand); for the user, its refusal as a stale context PIN too (a key
        // with a PIN of its own keeps its refusal). In the same step as the send, so no other send sees it
        // half done.
        RefusedPins.ForgetPin(checkedScope.Scope, pin.Pin);
        if (user == TokenUser.User)
        {
            RefusedPins.ForgetPin(RefusedPins.ContextScope(checkedScope.Identity), pin.Pin);
            // The module holds the login from here: its PIN is remembered in the same step, so a context login
            // never sees the login made and its PIN not yet known (a key with a PIN of its own refusing the user's
            // correct PIN would be taken for a stale one). Forgotten on every way out below but recording it.
            RefusedPins.RememberUserPin(checkedScope.Identity, pin.Pin);
        }
    }

    // Still under the transition, with a login the module made and this record has not recorded, so nothing else saw
    // it: logs it back out on its anchor (other sessions of the application share it), which the caller then closes.
    // If that fails, the module may keep it, and it is recorded as left on the token, for the next first login.
    private void LogBackOut(Pkcs11SessionCore anchor, TokenUser user, Pkcs11Library owner)
    {
        bool loggedOut = false;
        try
        {
            anchor.SendLogout();
            loggedOut = true;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
        {
            loggedOut = true;
        }
        catch (Exception ex) when (!Log.IsFatal(ex))
        {
            // A module failure, or a logger that threw on the way: the caller's exception is what it is told.
        }
        finally
        {
            if (!loggedOut)
            {
                MarkLeftBehind(user, owner);
                // Logged out once more on a session opened for it, as the class remarks give, once this thread lets go
                // of the semaphore (a hand-off), rather than left for the next first login.
                UnderTransition(LogOutLeftBehind);
            }
            // Objects other sessions found while this login was on the token were stamped as of no login: that state
            // is over.
            lock (_lock)
                _generation++;
        }
    }

    // The module answered CKR_OK to the login: its state must now show the user logged in. A module that accepts a
    // login it does not make (NSS answers an empty PIN with CKR_OK on a token that needs no login, and stays public)
    // would leave a login recorded that the next probe finds gone, ending every hold of it; refused here instead.
    // A probe that cannot be answered is no evidence either way, but an anchor lost is (a failover between the login and
    // the probe): its loss ends nothing yet, as the login is not recorded, so it fails the login here, which the caller
    // logs back out, or records as left on the token.
    private void ThrowIfNotLoggedIn(Pkcs11SessionCore anchor, TokenUser user, string method)
    {
        CKS? state;
        try
        {
            state = anchor.TrySendProbe();
        }
        catch (Pkcs11Exception) when (anchor.LostTo == CKR.CKR_OK)
        {
            return;
        }
        if (state is not { } reported || !TryUserOf(reported, out TokenUser? reportedUser) || reportedUser == user)
            return;
        throw new Pkcs11AuthenticationException(CKR.CKR_USER_NOT_LOGGED_IN, method,
            $"{method}: the module accepted the login to the token in slot {(ulong)_slotId}, but its session still " +
            $"reports {reported}, not the {Describe(user, username: null)} logged in. The token may not need a login " +
            "(TokenInfo.Flags without LoginRequired): use it without one.");
    }

    // The token in the slot must still be the one the caller selected the slot by (a URI, a serial number, a label):
    // its identity is read again now that the login's session is open, and before any PIN is sent. A token reports its
    // own identity, so this catches a token swapped in meanwhile, not one made to look like the selected one.
    private void ThrowIfAnotherToken(Pkcs11Library owner, TokenInfo? expected, string method)
    {
        if (expected is null)
            return;
        TokenInfo now = new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory: null).GetTokenInfo();
        if (!IsSameToken(now, expected))
            throw AnotherToken((ulong)_slotId, method);
    }

    /// <summary>
    /// Whether <paramref name="now"/> reports the token <paramref name="expected"/> did: label, serial number,
    /// manufacturer and model, compared as the bytes the module reported (fields that are not UTF-8 can decode to the
    /// same text).
    /// </summary>
    internal static bool IsSameToken(TokenInfo now, TokenInfo expected)
        => string.Equals(now.RawLabel, expected.RawLabel, StringComparison.Ordinal)
            && string.Equals(now.RawSerialNumber, expected.RawSerialNumber, StringComparison.Ordinal)
            && string.Equals(now.RawManufacturerId, expected.RawManufacturerId, StringComparison.Ordinal)
            && string.Equals(now.RawModel, expected.RawModel, StringComparison.Ordinal);

    /// <summary>The refusal of a call made through a slot that no longer holds the token it was selected by.</summary>
    internal static Pkcs11TokenException AnotherToken(ulong slotId, string method)
        => new(CKR.CKR_TOKEN_NOT_RECOGNIZED, method,
            $"{method}: the token in slot {slotId} is no longer the one the slot was selected by (its label, serial " +
            "number, manufacturer or model changed): it was removed or swapped. No PIN was sent. Select the slot again.");

    // Sends the first login on anchor. The module answering that a user is logged in already means a login this record
    // left on the token (its user recorded in _leftBehind), which is logged out on the new anchor before the login is
    // sent once more, so the PIN is checked; or a login made outside this library, which is refused. The new anchor's
    // state tells which user the module holds: a login of another user than the one left behind is not this record's.
    private void SendFirstLogin(Pkcs11SessionCore anchor, TokenUser user, SecurePin? pin, string? username, string method)
    {
        CKR answer;
        try
        {
            Send(anchor, user, pin, username);
            return;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_USER_ALREADY_LOGGED_IN
            or CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
        {
            answer = ex.ReturnValue;
        }

        TokenUser? leftBehind;
        lock (_lock)
            leftBehind = _leftBehind;
        // The module's own answer to this login says which user it holds, and is the only evidence taken: the new
        // anchor's state is not, since some modules report an SO login as a user's on a session opened after it
        // (Kryoptic), which would make an SO login left behind look foreign, or a foreign SO login look like a user's
        // left behind, and have it logged out.
        bool ours = leftBehind is { } behind
            && ((answer == CKR.CKR_USER_ALREADY_LOGGED_IN && behind == user)
                || (answer == CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN && behind != user));
        if (!ours)
        {
            throw new Pkcs11ForeignLoginException(answer, method,
                $"{method}: the token in slot {(ulong)_slotId} is logged in already, but not through this library " +
                "(another component calling the module directly, or another PKCS#11 wrapper in this process). The " +
                "library does not take over a login it did not make: log that login out where it was made, then log " +
                "in again.");
        }

        // This record's own login, ended without a C_Logout reaching the module: its generation is over and its
        // handles refused already, so logging it out costs no holder anything.
        try
        {
            anchor.SendLogout();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
        {
            // Gone meanwhile (its last session closed): nothing to log out.
        }
        lock (_lock)
        {
            _leftBehind = null;
            _generation++;
        }
        Send(anchor, user, pin, username);
    }

    /// <summary>
    /// Sends <c>C_InitPIN</c> on the anchor of the login <paramref name="hold"/> keeps, for
    /// <see cref="Pkcs11Login.InitUserPinWithPin"/> and <see cref="Pkcs11Login.InitUserPinWithPinpad"/>. The caller
    /// has checked the login is the Security Officer's, whose anchor is read/write: the "R/W SO Functions" state
    /// PKCS#11 v3.2 requires.
    /// </summary>
    /// <param name="hold">The caller's share of the login.</param>
    /// <param name="pin">The new normal-user PIN, or <see langword="null"/> for the protected authentication path.</param>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="hold"/> is released, or its login ended.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>; a lost anchor also ends the login.</exception>
    internal void InitUserPin(LoginHold hold, SecurePin? pin)
    {
        ArgumentNullException.ThrowIfNull(hold);

        // An operation: the login cannot be logged out under the send. The send waits for the anchor's lock.
        using IDisposable operation = EnterOperation();
        Pkcs11SessionCore anchor;
        lock (_lock)
        {
            if (hold.IsReleased || _anchor is null || hold.Generation != _generation)
                throw LoginEnded();
            anchor = _anchor;
        }

        try
        {
            anchor.SendInitPin(pin is null ? default : pin.Pin);
        }
        catch (ObjectDisposedException) when (!IsCurrent(hold.Generation))
        {
            // The module reported the login gone (MarkEnded) and the anchor was closed.
            throw LoginEnded();
        }
    }

    // PKCS#11 v3.2 C_Login: an SO login fails with CKR_SESSION_READ_ONLY_EXISTS while the application has a
    // read-only session open. Refused here from the sessions the library has open through any load of the module
    // (the record knows them); sessions opened outside the library are left to the module's answer.
    private void ThrowIfReadOnlySessionBlocksSo(TokenUser user, string method)
    {
        if (user != TokenUser.SecurityOfficer || _registry is null)
            return;
        int readOnly = _registry.Sessions(_slotId).ReadOnly;
        if (readOnly == 0)
            return;
        throw Pkcs11Exception.Create(CKR.CKR_SESSION_READ_ONLY_EXISTS, method,
            $"{method}: the Security Officer cannot log in to the token in slot {(ulong)_slotId} while this " +
            $"application has a read-only session open on it ({readOnly} open), as PKCS#11 forbids. Close the " +
            "read-only sessions first, or open read/write ones.");
    }

    // Opens the anchor read/write, so that it can do what any session of the login does should the token allow no
    // other. A user anchor falls back to read-only where the token refuses read/write (write-protected) or has no
    // read/write session left for this application; an SO anchor does not, as the SO has only read/write sessions
    // (PKCS#11 v3.2 C_OpenSession, CKR_SESSION_READ_WRITE_SO_EXISTS). CKR_SESSION_COUNT from the last attempt keeps
    // its code, with a message that says what holds the token's sessions.
    private Pkcs11SessionCore OpenAnchor(Pkcs11Library owner, TokenUser user, ILoggerFactory? loggerFactory)
    {
        // Throws ObjectDisposedException for a disposed owner. The anchor survives that owner's disposal
        // (it is shared by every load of the module), so it calls through a view that outlives the load.
        var slot = new Pkcs11Slot(owner, (ulong)_slotId, loggerFactory);
        try
        {
            try
            {
                return slot.OpenSessionCore(readWrite: true, anchor: true);
            }
            catch (Pkcs11Exception ex) when (user == TokenUser.User
                && ex.ReturnValue is CKR.CKR_TOKEN_WRITE_PROTECTED or CKR.CKR_SESSION_COUNT)
            {
                return slot.OpenSessionCore(readWrite: false, anchor: true);
            }
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_SESSION_COUNT)
        {
            throw NoSessionForLogin(ex);
        }
    }

    // The anchor could not open because the token allows this application
    // no more sessions. From the library's tally on the slot, which never counts sessions opened outside it.
    private Pkcs11SessionException NoSessionForLogin(Pkcs11Exception moduleAnswer)
    {
        int? open = _registry?.Sessions(_slotId) is { } tally ? tally.ReadOnly + tally.ReadWrite : null;
        string held = open switch
        {
            > 0 => $"it has {open} session(s) open on the slot through this library: dispose them, or log in first " +
                "and open sessions through the login (Pkcs11Login.OpenSession).",
            0 => "the sessions that use it up were not opened through this library: close them, or log in first and " +
                "open sessions through the login (Pkcs11Login.OpenSession).",
            _ => "close the sessions this application has open on it, or log in first and open sessions through the " +
                "login (Pkcs11Login.OpenSession).",
        };
        return new Pkcs11SessionException(CKR.CKR_SESSION_COUNT, OpOpenSession,
            $"{OpOpenSession}: a login needs a session of its own, and the token in slot {(ulong)_slotId} allows this " +
            $"application no further session of the kind asked for (read/write, or any); {held}", moduleAnswer);
    }

    private static void Send(Pkcs11SessionCore anchor, TokenUser user, SecurePin? pin, string? username)
    {
        CKU userType = user == TokenUser.SecurityOfficer ? CKU.CKU_SO : CKU.CKU_USER;
        ReadOnlySpan<byte> secret = pin is null ? default : pin.Pin;
        if (username is null)
            anchor.SendLogin(userType, secret);
        else
            anchor.SendLoginUser(userType, secret, username);
    }
}
