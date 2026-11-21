using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using Microsoft.Extensions.Logging;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// The holders that keep the login: shares taken without a PIN, and their release.
internal sealed partial class TokenLoginRecord
{
    /// <summary>
    /// Takes a share of the login held on the token for <paramref name="user"/> (and <paramref name="username"/>):
    /// for <see cref="Pkcs11Slot.TryShareLogin(out Pkcs11Login?)"/>. Null when no such login is held, or it is on its way
    /// out (its last holder gone). Calls the module only to check the slot still holds <paramref name="expectedToken"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// The token in the slot is not <paramref name="expectedToken"/> (<c>CKR_TOKEN_NOT_RECOGNIZED</c>).
    /// </exception>
    internal LoginHold? TryShare(Pkcs11Library owner, TokenUser user, string? username, TokenInfo? expectedToken = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        // The token is re-checked only when there is such a login to share: another user's makes this answer null, as
        // no login does, without calling the module.
        if (expectedToken is not null && Shareable(user, username))
            ThrowIfAnotherToken(owner, expectedToken, OpLogin);
        lock (_lock)
        {
            if (!ShareableLocked(user, username))
                return null;
            return AddHolderLocked(owner);
        }
    }

    private bool Shareable(TokenUser user, string? username)
    {
        lock (_lock)
            return ShareableLocked(user, username);
    }

    private bool ShareableLocked(TokenUser user, string? username)
        => _anchor is not null && _holders.Count != 0 && !_ending && _user == user
            && string.Equals(_username, username, StringComparison.Ordinal);

    /// <summary>
    /// Takes another share of the login <paramref name="existing"/> holds, without calling the module: for a
    /// session opened under a login, which keeps the login as long as it is open.
    /// </summary>
    /// <exception cref="Pkcs11LoginEndedException"><paramref name="existing"/> is released, or its login ended.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="owner"/> is being disposed.</exception>
    public LoginHold Share(LoginHold existing, Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(owner);
        if (!ReferenceEquals(existing.Record, this))
            throw new ArgumentException("The hold belongs to another token's login.", nameof(existing));

        lock (_lock)
        {
            if (existing.IsReleased || _anchor is null || _ending || existing.Generation != _generation)
                throw LoginEnded();
            return AddHolderLocked(owner);
        }
    }

    /// <summary>
    /// Releases every share that came through <paramref name="owner"/>, as its disposal does; the shares
    /// become inactive, and if no share of the current login is left, it is logged out. First takes back the anchor
    /// if it is lent to a session that came through <paramref name="owner"/> (the borrower's return runs, and it is
    /// disposed), so the final logout never meets a lent anchor.
    /// </summary>
    /// <remarks>From inside an operation, the logout is left pending until the operations in flight end.</remarks>
    public void ReleaseHoldersOf(Pkcs11Library owner)
    {
        ArgumentNullException.ThrowIfNull(owner);

        AnchorLoan? reclaimed;
        lock (_lock)
        {
            reclaimed = _loan is { } loan && ReferenceEquals(loan.Owner, owner) ? loan : null;
            // Marked as it is chosen, under the lock Return takes: a borrower disposed by its user before this point
            // has already returned the loan and is not chosen, so its refusals never blame the library.
            reclaimed?.MarkReclaimed();
        }

        // Outside the record's lock: the return takes the gate and the anchor's lock, and destroys the session objects
        // made through the borrower. It waits for an operation in flight on it.
        reclaimed?.Borrower.Dispose();

        TakenAnchor? taken = null;
        ILogger logger;
        lock (_lock)
        {
            int released = 0;
            for (int i = _holders.Count - 1; i >= 0; i--)
            {
                LoginHold hold = _holders[i];
                if (!ReferenceEquals(hold.Owner, owner) || !hold.TryMarkReleased())
                    continue;
                _holders.RemoveAt(i);
                released++;
            }
            if (released > 0 && _holders.Count == 0 && _anchor is not null)
                taken = RequestLogoutLocked(_generation);
            // The login outlives the library that made it while another holds it: a login it leaves on the token is
            // logged out through one still alive.
            if (ReferenceEquals(_loginOwner, owner) && _holders.Count > 0)
                _loginOwner = _holders[0].Owner;
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
    }

    /// <summary>
    /// Releases one share, from <see cref="LoginHold.Dispose"/>; the last share of the current login logs out, at once,
    /// or once the operations in flight end. Never throws for being inside an operation.
    /// </summary>
    internal void Release(LoginHold hold)
    {
        TakenAnchor? taken = null;
        ILogger logger;
        lock (_lock)
        {
            if (_holders.Remove(hold) && _holders.Count == 0 && _anchor is not null && hold.Generation == _generation)
                taken = RequestLogoutLocked(hold.Generation);
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
    }

    // Under _lock. Refuses an owner whose disposal has begun: Pkcs11Library.Dispose marks itself disposing before it
    // releases its holds (ReleaseHoldersOf, which takes this lock), so either that release sees this hold, or this
    // check sees the mark.
    private LoginHold AddHolderLocked(Pkcs11Library owner)
    {
        if (owner.IsDisposingOrDisposed)
            throw OwnerDisposed();
        return NewHolderLocked(owner);
    }

    // Under _lock, once the caller found the owner not disposing under the same lock: the owner's disposal sets its flag
    // before it releases its holds under _lock (ReleaseHoldersOf), so a hold added under that lock is released by it.
    private LoginHold NewHolderLocked(Pkcs11Library owner)
    {
        var hold = new LoginHold(this, owner, _generation);
        _holders.Add(hold);
        if (_loginOwner is null || _loginOwner.IsDisposingOrDisposed)
            _loginOwner = owner;
        return hold;
    }
}
