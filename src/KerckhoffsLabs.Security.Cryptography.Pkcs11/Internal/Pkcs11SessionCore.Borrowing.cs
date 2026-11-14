using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// A borrowing core (Borrow): one working on the anchor session of a token login, lent because the token allows no
// other session. What only a borrower has or does: its loan, the session objects made through it, and its return.
internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// The loan this core works under, for a borrower (<see cref="Borrow"/>); <see langword="null"/> for a core that
    /// owns its session, the anchor's own included.
    /// </summary>
    private readonly AnchorLoan? _loan;

    /// <summary>
    /// A borrower's session objects (<c>CKA_TOKEN</c> false) created through it, with what was read of each then,
    /// which its return destroys as <c>C_CloseSession</c> would; <see langword="null"/> for any other core. Under the
    /// lock.
    /// </summary>
    private readonly List<CreatedObject>? _sessionObjects;

    /// <summary>A session object a borrower created: its handle, and its <c>CKA_TOKEN</c>, class and label then.</summary>
    private readonly record struct CreatedObject(NativeCULong Handle, SessionObjectMark Mark);

    // On a borrower: the operations the anchor already carried abandoned when it was lent, so that only what this loan
    // adds is reported on its return.
    private readonly ulong _abandonedAtBorrow;

    /// <summary>
    /// Refuses a call on a disposed core, or on a borrower whose loan ended (the login ended, which closed the anchor
    /// it was lent) or was taken back by the disposal of the library it was lent through. A borrower's refusals name
    /// <see cref="Pkcs11Session"/>, the type its caller holds.
    /// </summary>
    private void ThrowIfUnusable()
    {
        if (_loan is { IsReclaimed: true } && _disposed)
        {
            throw new ObjectDisposedException(nameof(Pkcs11Session),
                "This session was the login's own session, lent because the token allows no other; the library that " +
                "lent it was disposed, which took it back. Dispose it.");
        }
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_loan is { IsEnded: true })
        {
            throw new ObjectDisposedException(nameof(Pkcs11Session),
                "This session was the login's own session, lent because the token allows no other; the login ended, " +
                "which closed it. Dispose it, and log in again.");
        }
    }

    /// <summary>
    /// Builds a borrowing core for <paramref name="loan"/>: a session on <paramref name="anchor"/>'s session handle,
    /// through the same view of the module, sharing its lock and what goes with it (the record sends' counter, the
    /// application lease's mark, and the operations abandoned on the session), with a policy, context authentication
    /// and caches of its own. It never disposes the handle, not even when it fails to be built.
    /// </summary>
    /// <exception cref="ObjectDisposedException"><paramref name="anchor"/> is closed.</exception>
    internal static Pkcs11SessionCore Borrow(Pkcs11SessionCore anchor, AnchorLoan loan, ILoggerFactory? loggerFactory, ICryptoPolicy? policy)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(loan);
        if (!anchor._isAnchorSide || anchor._loan is not null)
            throw new ArgumentException("Only the anchor session of a token login can be lent.", nameof(anchor));
        Pkcs11SessionHandle handle = anchor._sessionHandle;
        if (handle is null || handle.IsClosed)
            throw new ObjectDisposedException(nameof(Pkcs11Login), "This login has ended, which closed its own session. Log in again.");
        return new Pkcs11SessionCore(anchor._pkcs11Library, anchor._slotId, handle, loggerFactory, policy, anchor._lockState, loan);
    }

    /// <summary>
    /// On a borrower, remembers <paramref name="created"/> if it is a session object (<c>CKA_TOKEN</c> read false), so
    /// that returning the loan destroys it, as closing the session would (PKCS#11 v3.2 C_CloseSession), with its class
    /// and label, which the return checks again first. Under the lease, right after the call that created it. An
    /// object whose <c>CKA_TOKEN</c> cannot be read is left alone: a session object left until the anchor closes is
    /// better than a token object destroyed.
    /// </summary>
    private void RecordCreated(NativeCULong created)
    {
        if (_sessionObjects is null || (ulong)created == CK.CK_INVALID_HANDLE || IndexOfCreated(created) >= 0)
            return;
        SessionObjectMark mark = ObjectIdentityReader.ReadSessionObjectMark(_pkcs11Library, _sessionId, created);
        if (mark.IsToken == false)
            _sessionObjects.Add(new CreatedObject(created, mark));
    }

    /// <summary>On a borrower, forgets <paramref name="destroyed"/>, which the caller destroyed. Under the lease.</summary>
    private void ForgetDestroyed(NativeCULong destroyed)
    {
        int index = IndexOfCreated(destroyed);
        if (index >= 0)
            _sessionObjects!.RemoveAt(index);
    }

    // The position of handle in _sessionObjects, or -1 (also on a core that is not a borrower). A loop, not a lambda:
    // ForgetDestroyed runs on every core's C_DestroyObject, and allocates nothing on one that is not a borrower.
    private int IndexOfCreated(NativeCULong handle)
    {
        if (_sessionObjects is null)
            return -1;
        for (int i = 0; i < _sessionObjects.Count; i++)
        {
            if (_sessionObjects[i].Handle == handle)
                return i;
        }
        return -1;
    }

    /// <summary>
    /// A borrower's disposal: returns the anchor to the login, without <c>C_CloseSession</c> or <c>C_Logout</c>. Under
    /// the gate counted and the anchor's lock (an anchor-side core's order, waited for like any disposal): destroys
    /// the session objects made through it, unless the login ended (which closed the anchor, and them with it); leaves
    /// any operation it could not cancel with the anchor, for the next borrower to be told of; and returns the loan to
    /// the record, if it is still the current one. Never throws for the module's answers.
    /// </summary>
    private void ReturnLoan(AnchorLoan loan)
    {
        // Released after the lock, below: the reverse of the order taken.
        using IDisposable operation = _record.EnterOperation();
        bool lockTaken = false;
        try
        {
            Monitor.Enter(_busyLock, ref lockTaken);
            if (_disposed)
                return;

            if (!loan.IsEnded && _lostTo == CKR.CKR_OK)
            {
                DestroySessionObjects();
                if ((_operationsAbandoned & ~_abandonedAtBorrow) is not 0 and ulong added)
                    Log.LentSessionOperationsCarried(_logger, (ulong)_sessionId, added);
            }

            _record.Return(loan);
            _disposed = true;
        }
        finally
        {
            if (lockTaken)
                Monitor.Exit(_busyLock);
        }
    }

    // Under the anchor's lock, from ReturnLoan. Each handle is checked first to still be the session object created:
    // one destroyed through another session meanwhile may have had its number given to another object, a token object
    // even. CKA_TOKEN must read false, and the class and label read when it was created must still match.
    private void DestroySessionObjects()
    {
        if (_sessionObjects is not { Count: > 0 } created)
            return;

        bool added = false;
        try
        {
            _sessionHandle.DangerousAddRef(ref added);
            foreach ((NativeCULong handle, SessionObjectMark recorded) in created)
            {
                // Each handle is read, then either destroyed or logged as skipped: both branches do something, so
                // the loop is not a filter (and the borrower's return is no place for LINQ's allocations anyway).
                SessionObjectMark now = ObjectIdentityReader.ReadSessionObjectMark(_pkcs11Library, _sessionId, handle);
                if (now.IsToken == false && now.Matches(recorded))
                {
                    CKR rv = _pkcs11Library.C_DestroyObject(_sessionId, handle);
                    if (rv is not (CKR.CKR_OK or CKR.CKR_OBJECT_HANDLE_INVALID))
                        Log.LentSessionObjectNotDestroyed(_logger, (ulong)_sessionId, (ulong)handle, rv);
                }
                else
                {
                    Log.LentSessionObjectNotTheOneCreated(_logger, (ulong)_sessionId, (ulong)handle);
                }
            }
        }
        catch (ObjectDisposedException)
        {
            // The anchor or the library is gone, and the session objects with the session.
        }
        finally
        {
            created.Clear();
            if (added)
                _sessionHandle.DangerousRelease();
        }
    }
}
