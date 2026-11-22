using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    // -----------------------------------------------------------------------
    // InitPin — sent by the token login record (TokenLoginRecord) on an SO login's anchor, never by a session
    // of its own
    // -----------------------------------------------------------------------

    /// <summary>
    /// Sends <c>C_InitPIN</c> on this session. PKCS#11 v3.2 allows it only in the "R/W SO Functions" state, so it
    /// is meant for the read/write anchor session of a Security Officer login (see <see cref="TokenLoginRecord"/>).
    /// </summary>
    /// <param name="pin">
    /// The new normal-user PIN, straight from the pinned buffer its owner holds, with no transient copy; empty for
    /// the protected authentication path, which the interop layer marshals to <c>pPin = NULL_PTR</c>,
    /// <c>ulPinLen = 0</c>.
    /// </param>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_InitPIN</c>.</exception>
    internal void SendInitPin(ReadOnlySpan<byte> pin)
    {
        using var _ = AcquireForRecord();

        Log.SessionTrace(_logger, (ulong)_sessionId, pin.IsEmpty ? "InitPin (protected authentication path)" : "InitPin");
        if (pin.IsEmpty)
            ThrowIfNoPinpad(OpInitPIN);

        CKR rv = _pkcs11Library.C_InitPIN(_sessionId, pin);
        ThrowIfError(rv, OpInitPIN);
        // The user's PIN set: a refusal of it, as the user's or a stale context PIN, is wrong now; the SO's refusals stand,
        // and, for a PIN given, a key's own. One set on the pinpad may be any PIN refused before: every user and context
        // refusal is forgotten. A token that cannot be read has none to forget.
        if (TryTokenIdentity() is not { } identity)
            return;
        RefusedPins refused = _record.RefusedPins;
        if (pin.IsEmpty)
        {
            refused.Forget(_record.PinScopeOf(identity, TokenUser.User, username: null).Scope);
            refused.Forget(identity, RefusedPins.Purposes.Context);
        }
        else
        {
            refused.ForgetPin(_record.PinScopeOf(identity, TokenUser.User, username: null).Scope, pin);
            refused.ForgetPin(refused.ContextScope(identity), pin);
        }
    }

    /// <summary>
    /// Asks the module for this session's state (<c>C_GetSessionInfo</c>), for the login record: whether its anchor
    /// still holds the login, and which user the module has logged in. Never waits for the session's lock:
    /// <see langword="null"/> when another thread holds it (<see cref="TryAcquireForRecord"/>). A lost session is
    /// reported through <see cref="ThrowIfError"/>, which ends the login when this is the anchor.
    /// </summary>
    /// <returns>The session's state, or <see langword="null"/> when the session is busy.</returns>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetSessionInfo</c>.</exception>
    internal CKS? TrySendProbe()
    {
        using ExclusiveLease? lease = TryAcquireForRecord();
        if (lease is null)
            return null;

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetSessionInfo (login probe)");

        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, out CK_SESSION_INFO info);
        ThrowIfError(rv, OpGetSessionInfo);
        return (CKS)(ulong)info.State;
    }

    // -----------------------------------------------------------------------
    // SetPin
    // -----------------------------------------------------------------------

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <remarks>
    /// The old PIN is checked by the token, at the cost of one of its retries when wrong: one it refused before for that
    /// user is not sent again, and one it refuses now (<c>CKR_PIN_INCORRECT</c>) is remembered (<see cref="RefusedPins"/>),
    /// as for a login. Once changed, a refusal of the new PIN is forgotten.
    /// </remarks>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    /// <param name="refusedPinLifetime">How long a refused PIN is kept from the token (<see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/>).</param>
    /// <exception cref="Pkcs11AuthenticationException">
    /// <c>CKR_PIN_INCORRECT</c>, synthesized: the token refused <paramref name="oldPin"/> before; it is not sent again.
    /// </exception>
    public void SetPin(SecurePin oldPin, SecurePin newPin, TimeSpan? refusedPinLifetime = null)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetPin");

        // A token that cannot be read is not sent the old PIN: it could not be checked against the token's refusals,
        // nor a refusal remembered (Pkcs11Exception from C_GetTokenInfo).
        string identity = TokenFacts().Identity;
        RefusedPins refused = _record.RefusedPins;
        using SecurePin.Use oldUse = oldPin.BeginUse();
        using SecurePin.Use newUse = newPin.BeginUse();
        CKR rv = refused.Serialized(() =>
        {
            // Whose PIN this changes, read in the same step as the send; read again after it, so a login or logout of
            // another user meanwhile does not have the refusal filed under the wrong user.
            TokenLoginRecord.PinScope scope = _record.SetPinScope(identity);
            // The normal user's PIN is usually the context PIN too: one refused as a stale context PIN is not sent as the
            // old PIN either, as for a login.
            bool refusedBefore = refused.IsRefused(scope.Scope, oldPin.Pin);
            bool refusedAsContext = scope.Purpose == RefusedPins.Purposes.User
                && refused.IsRefused(refused.ContextScope(scope.Identity), oldPin.Pin);
            if (refusedBefore || refusedAsContext)
            {
                throw new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, OpSetPIN,
                    "The token refused this old PIN before, so it is not sent again: each wrong PIN costs one of the " +
                    "PIN's retries, and repeating it would lock the PIN. Fix the PIN's source. If the token's PIN was " +
                    "changed outside this library (to this PIN, or after it was put in the secret store), call " +
                    "Pkcs11Slot.ForgetRefusedPins().");
            }
            CKR answer = _pkcs11Library.C_SetPIN(_sessionId, oldPin.Pin, newPin.Pin);
            // Whose PIN it was is not known if another user (or username) logged in or out meanwhile: nothing remembered,
            // nothing forgotten.
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(_record.SetPinScope(identity).Scope, scope.Scope))
                return answer;
            // CKR_PIN_INCORRECT is the old PIN's (a retry spent); CKR_PIN_INVALID and CKR_PIN_LEN_RANGE, the new one's.
            if (answer == CKR.CKR_PIN_INCORRECT)
                refused.Refuse(scope.Purpose, scope.Identity, scope.Scope, oldPin.Pin, refusedPinLifetime);
            if (answer != CKR.CKR_OK)
                return answer;

            // The PIN changed: a refusal of the new one is wrong now, for the user's PIN as a stale context PIN too.
            // The user's PIN remembered for the login held is the new one. In the same step as the send, so a context
            // login meanwhile sees either the old state or the new.
            refused.ForgetPin(scope.Scope, newPin.Pin);
            if (scope.Purpose == RefusedPins.Purposes.User)
            {
                refused.ForgetPin(refused.ContextScope(scope.Identity), newPin.Pin);
                // Whether the user's login is held, decided under the record's lock in the same step that remembers its
                // PIN, so a logout that lands meanwhile cannot leave the new PIN remembered with no login.
                _record.ReplaceUserPin(scope.Identity, newPin.Pin);
            }
            return answer;
        });
        ThrowIfError(rv, OpSetPIN);
    }

    /// <summary>
    /// Modifies the PIN via the token's own pinpad, for tokens advertising
    /// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. Both the old and new PIN are entered on
    /// the device; PKCS#11 signals this by calling <c>C_SetPIN</c> with <c>pOldPin</c> and
    /// <c>pNewPin</c> both <c>NULL_PTR</c> — this overload passes empty spans for both, which the
    /// interop layer marshals to null pointers.
    /// </summary>
    public void SetPin()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetPin (protected authentication path)");
        ThrowIfNoPinpad(OpSetPIN);

        CKR rv = _pkcs11Library.C_SetPIN(_sessionId, default, default);
        ThrowIfError(rv, OpSetPIN);
        if (TryTokenIdentity() is not { } identity)
            return;
        TokenLoginRecord.PinScope scope = _record.SetPinScope(identity);
        // Changed to a PIN the library never sees: any refused before for that user (and username) may be it now; for
        // the user, as a context PIN too, and a key's own context refusals are forgotten with them. Other users' refusals
        // stand. The user's PIN remembered for the login held is forgotten: it is no longer the PIN.
        _record.RefusedPins.Forget(scope.Scope);
        if (scope.Purpose == RefusedPins.Purposes.User)
        {
            _record.RefusedPins.Forget(scope.Identity, RefusedPins.Purposes.Context);
            _record.RefusedPins.ForgetUserPin();
        }
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <returns>Information about a session</returns>
    public SessionInfo GetSessionInfo()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetSessionInfo");

        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, out CK_SESSION_INFO sessionInfo);
        ThrowIfError(rv, OpGetSessionInfo);

        return new SessionInfo(_sessionId, sessionInfo);
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as an array of bytes
    /// </summary>
    /// <returns>Operations state of a session</returns>
    public byte[] GetOperationState()
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "GetOperationState");

        return CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_GetOperationState(_sessionId, buffer, lengthOnly, out len),
            OpGetOperationState);
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from an array of bytes obtained with GetOperationState
    /// </summary>
    /// <param name="state">Array of bytes obtained with GetOperationState</param>
    /// <param name="encryptionKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing encryption or decryption operation in the restored session</param>
    /// <param name="authenticationKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing signature, MACing, or verification operation in the restored session</param>
    public void SetOperationState(byte[] state, ObjectHandle encryptionKey, ObjectHandle authenticationKey)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SetOperationState");

        ArgumentNullException.ThrowIfNull(state);

        // The keys the restored operations will use are judged like any other key put to use. A zero
        // handle (CK_INVALID_HANDLE) means "no key" and is not read. The operation's own mechanism and
        // the key it was started with live inside the opaque state blob and are not inspected; that gap
        // exists under every policy.
        if (!encryptionKey.IsInvalid)
            EnforceKeyStrength(encryptionKey, KeyStrengthSource.ExistingKey, null);
        if (!authenticationKey.IsInvalid)
            EnforceKeyStrength(authenticationKey, KeyStrengthSource.ExistingKey, null);

        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
        ThrowIfError(rv, OpSetOperationState);
    }

    // -----------------------------------------------------------------------
    // Login — sent by the token login record (TokenLoginRecord), never by a session of its own
    // -----------------------------------------------------------------------

    /// <summary>
    /// Sends <c>C_Login</c> on this session. Login state belongs to the application and the token, not
    /// to this session, so this is meant for the anchor session of the token's login record (see
    /// <see cref="TokenLoginRecord"/>).
    /// </summary>
    /// <param name="userType">Type of user.</param>
    /// <param name="pin">
    /// The PIN, straight from the pinned buffer its owner holds, with no transient copy; empty for the
    /// protected authentication path, which the interop layer marshals to <c>pPin = NULL_PTR</c>,
    /// <c>ulPinLen = 0</c>.
    /// </param>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_Login</c>.</exception>
    internal void SendLogin(CKU userType, ReadOnlySpan<byte> pin)
    {
        using var _ = AcquireForRecord();

        Log.SessionTrace(_logger, (ulong)_sessionId, "Login");

        if (pin.IsEmpty)
            Log.LoggingInProtectedPath(_logger, userType, (ulong)_sessionId);
        else
            Log.LoggingIn(_logger, userType, (ulong)_sessionId);

        CKR rv = _pkcs11Library.C_Login(_sessionId, userType, pin);
        ThrowIfError(rv, OpLogin);
    }

    // -----------------------------------------------------------------------
    // Context-specific login (CKA_ALWAYS_AUTHENTICATE) — sent by this session, inside one of its operations
    // -----------------------------------------------------------------------

    /// <summary>
    /// Checks, under the lease and before the operation's <c>C_*Init</c>, that <paramref name="context"/> may be sent:
    /// the pinpad only on a token with a protected authentication path, and never a PIN the token refused before for a
    /// context login (<see cref="RefusedPins"/>). Nothing for <see langword="null"/> (the key needs no context login).
    /// </summary>
    /// <exception cref="InvalidOperationException">The pinpad, on a token without a protected authentication path.</exception>
    /// <exception cref="Pkcs11AuthenticationException">
    /// <c>CKR_PIN_INCORRECT</c>, synthesized: the token refused this PIN before for a context login; it is not sent again.
    /// </exception>
    private void CheckContextLogin(ContextLogin? context)
    {
        if (context is null)
            return;
        if (context.Pin is null)
        {
            if (!TokenFacts().HasPinpad)
            {
                throw new InvalidOperationException(
                    "This key has CKA_ALWAYS_AUTHENTICATE and the session's ContextAuthentication is the pinpad, but the " +
                    "token has no protected authentication path (TokenFlags.ProtectedAuthenticationPath): PKCS#11 gives a " +
                    "context login without a PIN no meaning there, and the module may count it as a wrong PIN. Use " +
                    "ContextAuthentication.FromPin(...).");
            }
            return;
        }
        if (IsContextPinRefused(context))
            throw ContextPinRefusedBefore();
    }

    // Whether the token refused the context PIN before: for all its keys (a stale PIN), or for this key.
    private bool IsContextPinRefused(ContextLogin context)
    {
        (string identity, byte[] tokenScope, byte[] keyScope) = ContextScopes(context);
        RefusedPins refused = _record.RefusedPins;
        // Each checked, whatever the others say. A PIN the token refused as the normal user's login PIN is not tried as a
        // context PIN either, which is usually the user's: a stale secret costs one retry in all.
        bool forToken = refused.IsRefused(tokenScope, context.Pin!.Pin);
        bool forKey = refused.IsRefused(keyScope, context.Pin.Pin);
        // The user's: the one logged in, named or not (whose PIN the context login takes), or the unnamed user's.
        TokenLoginRecord.PinScope held = _record.SetPinScope(identity);
        byte[] userScope = held.Purpose == RefusedPins.Purposes.User
            ? held.Scope
            : _record.PinScopeOf(identity, TokenUser.User, username: null).Scope;
        bool asUser = refused.IsRefused(userScope, context.Pin.Pin);
        return forToken || forKey || asUser;
    }

    private static Pkcs11AuthenticationException ContextPinRefusedBefore()
        => new(CKR.CKR_PIN_INCORRECT, OpLogin,
            "The token refused this PIN before, for a key with CKA_ALWAYS_AUTHENTICATE, so it is not sent again: " +
            "each wrong PIN costs one of the PIN's retries, and repeating it would lock the PIN. Fix the PIN's " +
            "source. If the token's PIN was changed outside this library (to this PIN, or after it was put in the " +
            "secret store), call Pkcs11Slot.ForgetRefusedPins().");

    // The scopes of a context login's PIN (RefusedPins): the token's context logins, all keys; and this key's.
    private (string Identity, byte[] Token, byte[] Key) ContextScopes(ContextLogin context)
    {
        string identity = TokenFacts().Identity;
        RefusedPins refused = _record.RefusedPins;
        return (identity, refused.ContextScope(identity), refused.KeyContextScope(identity, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)context.Key.KeyType, context.Key.Id,
            context.Key.Label));
    }

    /// <summary>
    /// Refuses a call that would send no PIN (<c>pPin = NULL_PTR</c>, the pinpad) to a token without
    /// <c>CKF_PROTECTED_AUTHENTICATION_PATH</c>, before the module: PKCS#11 gives a NULL PIN a meaning only there, and a
    /// module may count it as a wrong PIN, or take it as an empty one. A token that cannot be read is not sent it either.
    /// </summary>
    /// <exception cref="InvalidOperationException">The token has no protected authentication path.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetTokenInfo</c>.</exception>
    internal void ThrowIfNoPinpad(string method)
    {
        if (TokenFacts().HasPinpad)
            return;
        throw NoPinpad(method, (ulong)_slotId);
    }

    /// <summary>The refusal of a pinpad call on a token without a protected authentication path.</summary>
    internal static InvalidOperationException NoPinpad(string method, ulong slotId)
        => new($"{method} on the pinpad: the token in slot {slotId} has no protected authentication path " +
            "(TokenFlags.ProtectedAuthenticationPath), so PKCS#11 gives a call without a PIN no meaning there, and the " +
            "module may count it as a wrong PIN or take it as an empty one. Nothing was sent. Give the PIN.");

    /// <inheritdoc cref="ThrowIfNoPinpad(string)"/>
    /// <remarks>For the login record, on its anchor, under the lease.</remarks>
    internal void ThrowIfNoPinpadForRecord(string method)
    {
        using var _ = AcquireForRecord();
        ThrowIfNoPinpad(method);
    }

    // The token's identity for RefusedPins, or null when the module cannot report it (C_GetTokenInfo failed). Under the
    // lease.
    private string? TryTokenIdentity()
    {
        try
        {
            return TokenFacts().Identity;
        }
        catch (Pkcs11Exception)
        {
            return null;
        }
    }

    // Whether the token has CKF_PROTECTED_AUTHENTICATION_PATH, and its identity for RefusedPins: read once per session
    // (C_GetTokenInfo), which cannot outlive its token. Under the lease.
    private (bool HasPinpad, string Identity) TokenFacts()
    {
        if (_tokenFacts is { } known)
            return known;
        CKR rv = _pkcs11Library.C_GetTokenInfo(_slotId, out CK_TOKEN_INFO info);
        Pkcs11Exception.ThrowIfError(rv, OpGetTokenInfo);
        (bool, string) facts = (((ulong)info.Flags & CKF.CKF_PROTECTED_AUTHENTICATION_PATH) != 0,
            RefusedPins.TokenIdentity(new TokenInfo(_slotId, info)));
        _tokenFacts = facts;
        return facts;
    }

    /// <summary>
    /// Re-authenticates the operation just begun (<c>C_Login(CKU_CONTEXT_SPECIFIC)</c>, PKCS#11 v3.2
    /// private_key_objects.md), with the PIN <paramref name="context"/> carries, or on the pinpad: called after a
    /// successful <c>C_*Init</c> and before the operation, under the same lease. Nothing when
    /// <paramref name="context"/> is <see langword="null"/> (the key needs none).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not a token login: no gate, no holder, no anchor; it is sent on this session and authenticates only the
    /// operation in progress. The PIN stays with <paramref name="context"/>, whose owner disposes it: a restarted
    /// operation sends it again.
    /// </para>
    /// <para>
    /// <c>CKR_OPERATION_NOT_INITIALIZED</c> means the key needs no re-authentication for this operation, which "will not
    /// be affected" (PKCS#11 v3.2 C_Login), unless the session no longer shows the user logged in: OpenSC answers it when
    /// the login is gone (a card reset by another process). So the session's state is read: a public one ends the token
    /// login (<see cref="TokenLoginRecord.MarkEnded"/>) and fails the operation with <c>CKR_USER_NOT_LOGGED_IN</c>; else
    /// the operation goes on. A PIN the token refused
    /// (<c>CKR_PIN_INCORRECT</c>, <c>CKR_PIN_INVALID</c>, <c>CKR_PIN_LEN_RANGE</c>) is recorded
    /// (<see cref="RefusedPins"/>), and shows the module enforces the context login: the operation carries on "as if
    /// C_Login had not been called", which <see cref="CancelAbandoned"/> may rely on to end it without output. On any
    /// failure the caller's <see cref="OperationScope"/> cancels the operation while this exception unwinds.
    /// <c>CKR_PIN_LOCKED</c> ends the token login (<see cref="TokenLoginRecord.MarkEnded"/>, which never waits): PKCS#11
    /// has the user logged out then; a module that keeps the login has it logged out by the record.
    /// </para>
    /// </remarks>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_Login</c>.</exception>
    private void AuthenticateContext(ContextLogin? context)
    {
        if (context is null)
            return;

        Log.ContextLoggingIn(_logger, (ulong)_sessionId, context.Pin is null ? " via protected authentication path" : "");
        // A pinpad PIN is typed afresh each time: nothing to check or remember. A PIN is checked again, sent and its
        // answer recorded in one step with every other PIN sent to the slot, so sessions that send the same stale PIN at
        // once cost it one retry, not one each.
        CKR rv = context.Pin is null
            ? _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, default)
            : _record.RefusedPins.Serialized(() => SendContextPin(context));
        switch (rv)
        {
            case CKR.CKR_OK:
                Interlocked.Increment(ref _contextLoginsAccepted);
                return;
            case CKR.CKR_OPERATION_NOT_INITIALIZED:
                if (!LoginGoneFromSession())
                {
                    Interlocked.Increment(ref _contextLoginsNotNeeded);
                    Log.ContextLoginNotNeeded(_logger, (ulong)_sessionId);
                    return;
                }
                _record.MarkEnded(CKR.CKR_USER_NOT_LOGGED_IN);
                _contextFailure = ContextFailure.NotAuthenticated;
                throw new Pkcs11AuthenticationException(CKR.CKR_USER_NOT_LOGGED_IN, OpLogin,
                    $"{OpLogin}: the module answered the context login {CKR.CKR_OPERATION_NOT_INITIALIZED}, and the " +
                    "session no longer shows the user logged in: the token's login is gone (the token reset or removed " +
                    "outside this application). Log in again.");
            case CKR.CKR_PIN_LOCKED:
                _record.MarkEnded(rv);
                _contextFailure = ContextFailure.NotAuthenticated;
                break;
            case CKR.CKR_PIN_INCORRECT:
                _contextFailure = ContextFailure.PinIncorrect;
                break;
            case CKR.CKR_PIN_INVALID or CKR.CKR_PIN_LEN_RANGE:
                // The PIN's form judged, maybe by the host side alone (OpenSC): no evidence the operation is held back.
                _contextFailure = ContextFailure.NotAuthenticated;
                break;
            case CKR.CKR_PIN_EXPIRED or CKR.CKR_FUNCTION_CANCELED:
                // The PIN expired, or the user cancelled on the pinpad: a user who retries must not find the session
                // held by the operation for good, so it is ended without being finished, as for a refused PIN.
                _contextFailure = ContextFailure.NotAuthenticated;
                break;
        }
        ThrowIfError(rv, OpLogin);
    }

    private int _contextLoginsAccepted;
    private int _contextLoginsNotNeeded;

    /// <summary>
    /// The context logins this session sent that the module accepted, and those it answered were not needed
    /// (<c>CKR_OPERATION_NOT_INITIALIZED</c>): for tests, which tell a module that enforces <c>CKA_ALWAYS_AUTHENTICATE</c>
    /// from one that ignores it.
    /// </summary>
    internal (int Accepted, int NotNeeded) ContextLogins
        => (Volatile.Read(ref _contextLoginsAccepted), Volatile.Read(ref _contextLoginsNotNeeded));

    // After a context login answered CKR_OPERATION_NOT_INITIALIZED, under the lease: whether the session's state is
    // public, so the answer meant no login (OpenSC), not no re-authentication needed. A state that cannot be read is no
    // evidence: the operation goes on, and its own call says what the module thinks.
    private bool LoginGoneFromSession()
    {
        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, out CK_SESSION_INFO info);
        return rv == CKR.CKR_OK && (CKS)(ulong)info.State is CKS.CKS_RO_PUBLIC_SESSION or CKS.CKS_RW_PUBLIC_SESSION;
    }

    // Under RefusedPins.Serialized: the context PIN checked again (another session may have just learnt it is wrong),
    // sent, and the answer recorded. The PIN the user's login held was made with, refused here, is this key's refusal (a
    // key with a PIN of its own) unless another key refused it too; any other is a stale PIN's, for all the token's keys
    // (RefusedPins.RefuseContextPin).
    private CKR SendContextPin(ContextLogin context)
    {
        // A PIN its caller keeps (ContextAuthentication.FromPin(SecurePin)) may be disposed meanwhile: zeroed only once
        // checked, sent and recorded.
        using SecurePin.Use use = context.Pin!.BeginUse();
        if (IsContextPinRefused(context))
        {
            // Refused by another session since this one's check, after this operation's C_*Init: no context login was
            // sent for this operation, which must be ended without being finished (CancelAbandoned).
            _contextFailure = ContextFailure.NotAuthenticated;
            throw ContextPinRefusedBefore();
        }
        (string identity, byte[] tokenScope, byte[] keyScope) = ContextScopes(context);
        RefusedPins refused = _record.RefusedPins;
        ReadOnlySpan<byte> pin = context.Pin.Pin;
        CKR rv = _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, pin);
        if (rv == CKR.CKR_OK)
        {
            // Accepted for this key: a refusal of it here is wrong now. Another key's refusal of it stands. It is not
            // remembered as accepted: only the user's login PIN is (RefusedPins).
            refused.ForgetPin(tokenScope, pin);
            refused.ForgetPin(keyScope, pin);
        }
        else if (RefusedPins.IsPinRefusal(rv))
        {
            refused.RefuseContextPin(identity, tokenScope, keyScope, pin, context.RefusedPinLifetime);
        }
        return rv;
    }

    /// <summary>
    /// Sends <c>C_LoginUser</c> (PKCS#11 v3.0) on this session: a user type plus a username, for tokens
    /// with named user accounts. Meant for the login record's anchor session, as <see cref="SendLogin"/> is.
    /// </summary>
    /// <param name="userType">Type of user.</param>
    /// <param name="pin">The PIN; empty for the protected authentication path, as for <see cref="SendLogin"/>.</param>
    /// <param name="username">Account username, sent UTF-8 encoded. Must not be null or empty. Never logged.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="username"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="username"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from C_LoginUser. <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> indicates the loaded library is v2.40 or otherwise does not export C_LoginUser.</exception>
    internal void SendLoginUser(CKU userType, ReadOnlySpan<byte> pin, string username)
    {
        using var _ = AcquireForRecord();
        ArgumentNullException.ThrowIfNull(username);
        if (username.Length == 0)
            throw new ArgumentException("Username must not be empty.", nameof(username));

        ThrowIfUnusable();

        Log.SessionTrace(_logger, (ulong)_sessionId, "LoginUser");

        Log.LoggingInUser(_logger, userType, (ulong)_sessionId);

        byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
        try
        {
            CKR rv = _pkcs11Library.C_LoginUser(_sessionId, userType, pin, usernameBytes);
            ThrowIfError(rv, OpLoginUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(usernameBytes);
        }
    }
}
