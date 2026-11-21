using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using Microsoft.Extensions.Logging;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// Lending the login's own session to a session of the login, on a token that allows no other.
internal sealed partial class TokenLoginRecord
{
    /// <summary>
    /// Lends the anchor of the login <paramref name="hold"/> keeps as the working session of a
    /// <see cref="Pkcs11Login.OpenSession()"/> whose <c>C_OpenSession</c> the module answered <c>CKR_SESSION_COUNT</c>:
    /// returns the borrowing core, or <see langword="null"/> with <paramref name="refusal"/> saying why it cannot be
    /// lent (it is lent already, or it is read-only and <paramref name="access"/> is read/write). Calls no module.
    /// </summary>
    /// <param name="hold">The share the new session will keep: it must be of the current login.</param>
    /// <param name="owner">The library the session comes through; its disposal reclaims the loan.</param>
    /// <param name="access">The access asked for: a read/write anchor serves either, a read-only one only <see cref="SessionAccess.ReadOnly"/>.</param>
    /// <param name="policy">The borrower's policy; <see langword="null"/> means <see cref="CryptoPolicy.Recommended"/>.</param>
    /// <param name="loggerFactory">The borrower's logger factory.</param>
    /// <param name="refusal">Why the anchor was not lent, for the <c>CKR_SESSION_COUNT</c> the caller throws.</param>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="hold"/> is released or its login ended.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    internal Pkcs11SessionCore? TryLend(LoginHold hold, Pkcs11Library owner, SessionAccess access, ICryptoPolicy? policy,
        ILoggerFactory? loggerFactory, out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(hold);
        ArgumentNullException.ThrowIfNull(owner);

        Pkcs11SessionCore anchor;
        long generation;
        lock (_lock)
        {
            refusal = LendRefusalLocked(hold, access);
            if (refusal is not null)
                return null;
            anchor = _anchor!;
            generation = _generation;
        }

        // Built outside the lock: it runs the caller's logger factory. Another thread may lend the anchor, or the
        // login end, meanwhile; checked again below before the loan is recorded.
        AnchorLoan loan;
        Pkcs11SessionCore borrower;
        try
        {
            loan = new AnchorLoan(anchor, owner, generation, anchor.SessionId);
            borrower = Pkcs11SessionCore.Borrow(anchor, loan, loggerFactory, policy);
        }
        catch (ObjectDisposedException) when (!IsCurrent(generation))
        {
            // The login ended meanwhile, which closed the anchor.
            throw LoginEnded();
        }
        loan.Borrower = borrower;
        BetweenLendPhases?.Invoke();

        ILogger logger;
        lock (_lock)
        {
            try
            {
                refusal = LendRefusalLocked(hold, access);
                if (refusal is null && (!ReferenceEquals(_anchor, anchor) || _generation != generation))
                    throw LoginEnded();
                // As AddHolderLocked: a loan recorded after the owner's disposal released its holds would never be reclaimed.
                if (owner.IsDisposingOrDisposed)
                    throw OwnerDisposed();
            }
            catch
            {
                loan.MarkEnded();
                throw;
            }

            if (refusal is not null)
            {
                // Never lent: nothing to return, and nothing else holds the borrower.
                loan.MarkEnded();
                return null;
            }
            _loan = loan;
            logger = _logger;
        }

        Log.AnchorLent(logger, (ulong)_slotId, loan.SessionHandle);
        return borrower;
    }

    /// <summary>
    /// Test seam: runs in <see cref="TryLend"/> on the lending thread after the borrower is built and before the loan
    /// is recorded, holding no lock, so a test can end the login, start the owner's disposal, or lend the anchor
    /// elsewhere in between. <see langword="null"/> outside tests.
    /// </summary>
    internal Action? BetweenLendPhases { get; set; }

    // Under _lock. Null when the anchor can be lent for access; else the refusal's message. A hold that is not of the
    // current login throws, as Share does.
    private string? LendRefusalLocked(LoginHold hold, SessionAccess access)
    {
        if (hold.IsReleased || _anchor is null || hold.Generation != _generation)
            throw LoginEnded();
        if (_loan is not null)
        {
            return $"{OpOpenSession}: the token in slot {(ulong)_slotId} allows this application no further " +
                "session of the kind asked for, so the login lends its own session as the working session, and it is " +
                "already lent to another session of the login. Dispose that session first: on this token a login has " +
                "one working session at a time.";
        }
        if (access == SessionAccess.ReadWrite && !_anchor.IsReadWrite)
        {
            return $"{OpOpenSession}: the token in slot {(ulong)_slotId} allows this application no more sessions of " +
                "that kind, and the login's own session, which it would lend, is read-only (the token refused a " +
                "read/write session when the login was made). Open a read-only session (SessionAccess.ReadOnly).";
        }
        return null;
    }

    /// <summary>
    /// Takes back the anchor lent under <paramref name="loan"/>, from the borrower's disposal; nothing when it is no
    /// longer the current loan (the login ended meanwhile, or it was already returned).
    /// </summary>
    internal void Return(AnchorLoan loan)
    {
        ArgumentNullException.ThrowIfNull(loan);
        ILogger logger;
        lock (_lock)
        {
            if (!ReferenceEquals(_loan, loan))
                return;
            _loan = null;
            logger = _logger;
        }
        Log.Quietly(() => Log.AnchorReturned(logger, (ulong)_slotId, loan.SessionHandle));
    }

    // Under _lock. Ends the loan of the anchor, if any, before the anchor closes.
    private void EndLoanLocked()
    {
        _loan?.MarkEnded();
        _loan = null;
    }
}
