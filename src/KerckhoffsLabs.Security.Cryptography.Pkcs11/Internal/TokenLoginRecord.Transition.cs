using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// The transition semaphore: one login or logout at a time, and the work handed off to its holder.
internal sealed partial class TokenLoginRecord
{
    // Takes the transition semaphore, waiting its turn, and records this thread as its holder.
    private void AcquireTransition()
    {
        ThrowIfHoldingTransition();
        _transition.Wait();
        TookTransition();
    }

    // Records this thread as the holder of the semaphore it just took.
    private void TookTransition()
    {
        Volatile.Write(ref _transitionOwner, Environment.CurrentManagedThreadId);
        WhileHoldingTransition?.Invoke();
    }

    // The semaphore is not reentrant: a thread that holds it (a logger the library calls while logging in, logging in
    // to the same token) would wait for itself forever.
    private void ThrowIfHoldingTransition()
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
        {
            throw new InvalidOperationException(
                "A login to this token is already being made on this thread (code the library called while logging in, " +
                "such as a logger): it cannot log in, share or log out on the same token until that login is done.");
        }
    }

    // Runs what was handed to this thread while it held the semaphore, or posted to its holder (UnderTransitionOrPost),
    // then releases it. An action posted after the hand-offs ran, by a thread that then found the semaphore still
    // taken, is run here too: the semaphore is taken back, if free, until none is left.
    private void ReleaseTransition()
    {
        while (true)
        {
            try
            {
                RunHandOffs();
            }
            finally
            {
                Volatile.Write(ref _transitionOwner, 0);
                _transition.Release();
            }
            lock (_lock)
            {
                if (_handOffs.Count == 0)
                    return;
            }
            // Free: this thread runs them. Taken: its new holder runs them as it releases it.
            if (!_transition.Wait(0))
                return;
            TookTransition();
        }
    }

    // Runs every hand-off, each even if the one before it threw. A throw is logged and dropped: hand-offs are logouts
    // and their follow-ups, run on paths that never throw (a release, an operation's end), and the caller's own outcome
    // (a login just made, whose hold would leak) must not be replaced by one.
    private void RunHandOffs()
    {
        while (true)
        {
            Action next;
            ILogger logger;
            lock (_lock)
            {
                if (_handOffs.Count == 0)
                    return;
                next = _handOffs[0];
                _handOffs.RemoveAt(0);
                logger = _logger;
            }
            try
            {
                next();
            }
            catch (Exception ex) when (!Log.IsFatal(ex))
            {
                Log.Quietly(() => Log.TokenHandOffFailed(logger, (ulong)_slotId, ex));
            }
        }
    }

    // Runs action under the transition semaphore. On the thread that holds it already (a logout due as the record's
    // own send ends, a login's probe finding its anchor lost), the semaphore cannot be taken again: the action is
    // handed to this thread, to run before it releases the semaphore.
    internal void UnderTransition(Action action)
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
        {
            lock (_lock)
                _handOffs.Add(action);
            return;
        }
        AcquireTransition();
        try
        {
            action();
        }
        finally
        {
            ReleaseTransition();
        }
    }

    // Runs action under the transition semaphore if it is free, or hands it to the thread holding it, which runs it as
    // it releases the semaphore (ReleaseTransition): never waits. For the logout of a login left on the token, sent from
    // the end of an operation, while that operation's session lock is held: waiting there for a first login that holds
    // the semaphore across a pinpad prompt would stall the session. A first login logs out such a login itself
    // (SendFirstLogin), so nothing waits for this one. And for the final logout from inside an operation (LogOut).
    private void UnderTransitionOrPost(Action action)
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId || !_transition.Wait(0))
        {
            lock (_lock)
                _handOffs.Add(action);
            // The holder may have run its hand-offs and released since: take the semaphore now, if free, to run them.
            if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId || !_transition.Wait(0))
                return;
            TookTransition();
            ReleaseTransition();
            return;
        }
        TookTransition();
        try
        {
            action();
        }
        finally
        {
            ReleaseTransition();
        }
    }
}
