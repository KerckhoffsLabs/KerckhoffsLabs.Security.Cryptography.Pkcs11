using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// The end of a login: logout once the last holder goes, a login that ended on its own, and one left on the token.
internal sealed partial class TokenLoginRecord
{
    // Waits for an ended login's anchor to close, outside the semaphore: on a token that allows one session, the next
    // anchor would be refused while it is open. Not from inside an operation, which the close may be waiting for. The
    // close is deferred only while another thread holds the anchor's lock (a lent anchor's operation), so this waits for
    // that operation to end, as a first login waits for operations in flight anyway.
    private void WaitForAnchorClosed()
    {
        if (t_operationsOnThread == 0 && Volatile.Read(ref _anchorClosing) is { IsCompleted: false } closing)
            closing.Wait();
    }

    // Waits until no logout is pending or in flight; throws from inside an operation, which a pending logout may wait for.
    private void WaitForNoLogoutUnderway()
    {
        if (_noLogoutUnderway.IsSet)
            return;
        // Inside an operation on any token: on this one, the logout waits for that operation; on another, a logout pending
        // there may wait for an operation whose thread is waiting here, with no way out for either.
        if (t_operationsOnThread > 0)
        {
            throw new InvalidOperationException(
                "A login cannot be made from inside an operation (on this token or another) while the previous login's " +
                "logout waits for the operations in flight to finish: log in outside the operation.");
        }
        _noLogoutUnderway.Wait();
    }

    /// <summary>
    /// Records that the module reported the login gone (the anchor session lost, or <c>CKR_PIN_LOCKED</c> from
    /// a context-specific login): starts a new generation at once, so every existing share is inactive, no
    /// longer counts, and sends no <c>C_Logout</c>; and closes the anchor, so the next <see cref="Login"/>
    /// starts afresh.
    /// </summary>
    /// <param name="reason">The return code that reported it, for the log.</param>
    /// <remarks>Never waits, so an operation in flight may call this.</remarks>
    public void MarkEnded(CKR reason) => EndLogin(reason, onlyAnchor: null);

    // MarkEnded, or, with onlyAnchor, only while that session is the anchor (checked under the same hold of the
    // lock that ends the login). The anchor's own loss (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED,
    // CKR_DEVICE_REMOVED, CKR_TOKEN_NOT_PRESENT) can leave the module logged in, through the application's other
    // sessions: the last two can be transient on a network HSM, and do not say the module dropped anything. That login
    // is recorded (_leftBehind) and logged out as soon as no operation is in flight, on a session opened for it
    // (LogOutLeftBehind), which first reads the session state the module reports: a token really removed shows no
    // login, or opens no session, and the next first login, which then succeeds, clears the record. CKR_PIN_LOCKED from a
    // context login is recorded the same way: PKCS#11 has the user logged out then, but OpenSC keeps the login (its
    // context PIN may be a signature PIN of its own), and the probe tells which. After a public state reported
    // (moduleLoggedOut) or the module finalized (CKR_CRYPTOKI_NOT_INITIALIZED), the module holds nothing.
    private void EndLogin(CKR reason, Pkcs11SessionCore? onlyAnchor, bool moduleLoggedOut = false)
    {
        Pkcs11SessionCore? anchor;
        ILogger logger;
        TaskCompletionSource ended;
        bool logOutLeftBehind = false;
        lock (_lock)
        {
            if (onlyAnchor is not null && !ReferenceEquals(_anchor, onlyAnchor))
                return;
            _generation++;
            _holders.Clear();
            // Before the anchor closes: its borrower refuses every call from now on, and its return sends nothing.
            EndLoanLocked();
            anchor = _anchor;
            TokenUser? user = _user;
            _anchor = null;
            _user = null;
            _username = null;
            logger = _logger;
            ended = _loginEnded;
            _pendingLogout = null;
            _ending = false;
            RefusedPins.ForgetUserPin();
            if (anchor is not null)
            {
                if (!moduleLoggedOut && reason is CKR.CKR_SESSION_HANDLE_INVALID or CKR.CKR_SESSION_CLOSED
                        or CKR.CKR_DEVICE_REMOVED or CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_PIN_LOCKED)
                {
                    _leftBehind = user;
                    if (_activeOperations == 0)
                        logOutLeftBehind = true;
                    else
                        _leftBehindLogoutPending = true;
                }
                else
                {
                    _leftBehind = null;
                }
            }
            SignalIfNoLogoutLocked();
        }

        if (anchor is null)
            return;
        // Closed before the log: a logger that throws cannot leave the anchor open. Never waits for the anchor's lock:
        // this may run holding the transition semaphore (a probe that found the login gone), or inside an operation, and
        // the lock's holder (a borrower's operation, say) may be waiting for either; it then closes once the lock is free,
        // and the next first login waits for that (_anchorClosing), so it is not refused for the session still open.
        Volatile.Write(ref _anchorClosing, anchor.DisposeWithoutWaiting());
        ended.TrySetResult();
        if (logOutLeftBehind)
            UnderTransitionOrPost(LogOutLeftBehind);
        Log.TokenLoginEnded(logger, (ulong)_slotId, reason);
    }

    /// <summary>
    /// Ends the login when <paramref name="anchor"/>, the session it was made on, is reported lost (#363's codes),
    /// as <see cref="MarkEnded"/> does; nothing when <paramref name="anchor"/> is not this record's current anchor
    /// (a first login's anchor that failed before the login was recorded, or one already logged out).
    /// </summary>
    internal void AnchorLost(Pkcs11SessionCore anchor, CKR reason)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        EndLogin(reason, anchor);
    }

    // Under _lock, once the last share of the login of generation has gone: takes the anchor for the logout now, or,
    // with operations in flight, leaves the logout pending for the last of them (ExitOperation). The login is ending
    // from now on: not current, so no operation that starts now uses its private handles, and none of those counts.
    private TakenAnchor? RequestLogoutLocked(long generation)
    {
        if (_activeOperations == 0)
            return TakeAnchorForLogoutLocked(generation);
        _pendingLogout = generation;
        _ending = true;
        _noLogoutUnderway.Reset();
        return null;
    }

    // Under _lock. Lets a waiting Login go on once no logout is pending or in flight.
    private void SignalIfNoLogoutLocked()
    {
        if (_pendingLogout is null && !_logoutInFlight)
            _noLogoutUnderway.Set();
    }

    // The anchor of a login taken out of the record for its logout, and who was logged in.
    private readonly record struct TakenAnchor(Pkcs11SessionCore Anchor, TokenUser User);

    // The final logout, of an anchor taken out of the record (TakeAnchorForLogoutLocked) with no operation in flight,
    // under the transition semaphore: so this C_Logout never lands after the next C_Login.
    // From inside an operation (on another token, or one not counted here), it is handed to the semaphore's holder rather
    // than waited for: releasing a share never blocks there (UnderTransitionOrPost). The logout is then underway until
    // that holder runs it, so a login from the same operation is refused (WaitForNoLogoutUnderway) rather than made.
    private void LogOut(TakenAnchor taken, ILogger logger)
    {
        if (t_operationsOnThread > 0)
            UnderTransitionOrPost(() => LogOutHeld(taken, logger));
        else
            UnderTransition(() => LogOutHeld(taken, logger));
    }

    // Under the transition semaphore. A C_Logout that fails, or never reaches the module (a logger that throws first),
    // leaves the module possibly logged in: recorded (_leftBehind), and logged out once more on a session opened for it
    // (LogOutLeftBehind) before the semaphore is released. The anchor is closed regardless, and closing it may itself
    // end the login (it can be the application's last session).
    private void LogOutHeld(TakenAnchor taken, ILogger logger)
    {
        bool loggedOut = false;
        CKR? failure = null;
        bool anchorClosed = false;
        try
        {
            using (taken.Anchor)
            {
                try
                {
                    taken.Anchor.SendLogout();
                    loggedOut = true;
                }
                catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN)
                {
                    loggedOut = true;
                }
                catch (Pkcs11Exception ex)
                {
                    failure = ex.ReturnValue;
                }
                catch (ObjectDisposedException)
                {
                    anchorClosed = true;
                }
                catch (Exception ex) when (!Log.IsFatal(ex))
                {
                    // Not the module's: a logger that threw on the way to C_Logout (the module's own failures are
                    // Pkcs11Exception). Dispose never throws, so this is a logout that did not reach the module: the
                    // login is left behind and logged out below.
                }
            }
        }
        finally
        {
            TaskCompletionSource ended;
            lock (_lock)
            {
                if (!loggedOut)
                    _leftBehind = taken.User;
                // Objects found while the C_Logout was on its way were stamped as of a login never current again; a
                // new generation also ends every stamp taken before it.
                _generation++;
                _logoutInFlight = false;
                _ending = false;
                SignalIfNoLogoutLocked();
                ended = _loginEnded;
            }
            ended.TrySetResult();
            if (!loggedOut)
                UnderTransition(LogOutLeftBehind);
        }

        if (failure is { } rv)
            Log.Quietly(() => Log.TokenLogoutFailed(logger, (ulong)_slotId, rv));
        if (anchorClosed)
            Log.Quietly(() => Log.TokenLogoutAnchorClosed(logger, (ulong)_slotId));
    }

    // A failed log-back-out of a login nothing saw (FirstLogin, its owner disposed): the module may keep it.
    private void MarkLeftBehind(TokenUser user, Pkcs11Library owner)
    {
        lock (_lock)
        {
            _leftBehind = user;
            _loginOwner ??= owner;
        }
    }

    // Under the transition semaphore. Logs out a login this record left on the token (_leftBehind), on a session opened
    // for it through the library that made the login: login state belongs to the application, so C_Logout on any of
    // its sessions ends it (PKCS#11 v3.2 C_Logout). That session's state tells first whether the module still holds
    // that user's login: a public state means nothing is left; another user's login is not this record's, and is left
    // alone. When no session can be opened, or the C_Logout fails, the login stays recorded, and the next first login
    // logs it out (SendFirstLogin).
    private void LogOutLeftBehind()
    {
        TokenUser leftBehind;
        Pkcs11Library? owner;
        lock (_lock)
        {
            if (_anchor is not null || _leftBehind is not { } user)
                return;
            // Decided when no operation was counted, and run maybe later (handed to the thread holding the semaphore):
            // with operations counted since, the last of them sends it instead. This narrows the window, it does not
            // close it: an operation may still start while the session below opens. Such an operation finds the
            // left-behind login's handles refused already, so a C_Logout inside it costs it nothing private.
            if (_activeOperations > 0)
            {
                _leftBehindLogoutPending = true;
                return;
            }
            leftBehind = user;
            owner = _loginOwner;
        }
        if (owner is null)
            return;

        // Through the library that made the login; once its disposal has begun, through the module-wide view the anchor
        // uses (a session outliving its load), so another load that keeps the module does not keep the login too. Once
        // that library is disposed in full (its view of the module gone), through another load still alive; with none,
        // the module is finalized or about to be, which ends the login.
        Pkcs11Library? via = owner.LowLevelLibrary is null ? _registry?.LiveLibrary() : owner;
        if (via is null)
            return;
        Pkcs11SessionCore session;
        try
        {
            session = new Pkcs11Slot(via, (ulong)_slotId, loggerFactory: null)
                .OpenSessionCore(readWrite: leftBehind == TokenUser.SecurityOfficer, anchor: via.IsDisposingOrDisposed);
        }
        catch (Pkcs11Exception)
        {
            return;
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        using (session)
        {
            if (!LoggedOutOn(session, leftBehind))
                return;
        }

        lock (_lock)
        {
            if (_anchor is null && _leftBehind is not null)
            {
                _leftBehind = null;
                // Objects found while it was on the token were stamped as of a login: that state is over.
                _generation++;
            }
        }
    }

    // Logs out the login of leftBehind left on the token, on session: whether it is gone now. Gone only on evidence: a
    // public state, or the C_Logout sent. A state that shows another user (a module may report an SO login as a user's
    // on a session opened after it, as Kryoptic does) or none at all leaves the login recorded, its handles refused, for
    // the next first login to settle.
    private static bool LoggedOutOn(Pkcs11SessionCore session, TokenUser leftBehind)
    {
        try
        {
            if (session.TrySendProbe() is not { } state || !TryUserOf(state, out TokenUser? moduleUser))
                return false;
            if (moduleUser is null)
                return true;
            if (moduleUser != leftBehind)
                return false;
            session.SendLogout();
            return true;
        }
        catch (Pkcs11Exception ex)
        {
            return ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN;
        }
        catch (Exception ex) when (!Log.IsFatal(ex))
        {
            // A logger that threw on the way (the module's failures are Pkcs11Exception): the login stays recorded, for
            // the next first login to settle; this runs on disposal paths, which never throw.
            return false;
        }
    }

    // Under _lock, with no operation counted. Takes the anchor out of the record, for LogOut to close, if the login
    // of generation is still current and unheld; else null, and the record is left as it was. From here on the login
    // is not current, so an operation that starts now finds its private handles refused.
    private TakenAnchor? TakeAnchorForLogoutLocked(long generation)
    {
        if (_holders.Count != 0 || _anchor is null || _user is not { } user || _generation != generation)
            return null;
        // Not expected: a lent anchor has its borrower's hold. Should one be left, it is not lent any longer.
        EndLoanLocked();
        Pkcs11SessionCore anchor = _anchor;
        _anchor = null;
        _user = null;
        _username = null;
        _ending = false;
        RefusedPins.ForgetUserPin();
        _logoutInFlight = true;
        _noLogoutUnderway.Reset();
        return new TakenAnchor(anchor, user);
    }
}
