using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

// Operation tracking: the operations in flight on the token, by epoch, that a login or logout waits for.
internal sealed partial class TokenLoginRecord
{
    // The writes of the thread's depth: static, as the depth is the thread's, across all records.
    private static void EnterOperationOnThread() => t_operationsOnThread++;

    private static void ExitOperationOnThread() => t_operationsOnThread--;

    /// <summary>
    /// Counts an operation that relies on the login until the returned lease is disposed: the final logout waits for
    /// it (see the class remarks). Never waits. Dispose it on the thread that took it, once.
    /// </summary>
    /// <remarks>
    /// Not counted: an operation on the thread that holds the transition semaphore (the record's own sends, which no
    /// logout can race, as a logout needs that semaphore), and one that starts while the login is ending (its last
    /// holder gone): such an operation finds private handles refused, so the logout need not wait for it.
    /// </remarks>
    public IDisposable EnterOperation()
    {
        if (Volatile.Read(ref _transitionOwner) == Environment.CurrentManagedThreadId)
            return NoOperation.Instance;

        bool counted;
        int epoch;
        LoginStamp stamp;
        lock (_lock)
        {
            counted = !_ending;
            if (counted)
                _activeOperations++;
            epoch = _operationEpoch;
            _operationsByEpoch[epoch] = _operationsByEpoch.GetValueOrDefault(epoch) + 1;
            stamp = StampLocked();
        }
        int depth = _operationDepth.Value;
        if (depth == 0)
            _operationStamp.Value = stamp;
        _operationDepth.Value = depth + 1;
        EnterOperationOnThread();
        return new OperationLease(this, counted, epoch, Environment.CurrentManagedThreadId);
    }

    // Under the transition semaphore, before a first login: with operations in flight on the token's sessions, starts a
    // new epoch and returns the one they began in or before, for the login to wait for; null when none is in flight.
    private int? StartOperationEpoch()
    {
        lock (_lock)
            return _operationsByEpoch.Count == 0 ? null : _operationEpoch++;
    }

    // Outside the transition semaphore: waits until every operation that began in epoch or an epoch before it has ended.
    // Bounded by those operations alone: one that starts later is in a later epoch.
    private void WaitForOperationsBefore(int epoch)
    {
        WhileWaitingForOperations?.Invoke();
        while (true)
        {
            Task ended;
            lock (_lock)
            {
                bool any = false;
                foreach (int began in _operationsByEpoch.Keys)
                    any |= began <= epoch;
                if (!any)
                    return;
                _operationsEnded ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                ended = _operationsEnded.Task;
            }
            ended.Wait();
        }
    }

    // The end of an operation: the last counted one to end sends a logout left pending, and the logout of a login left
    // on the token.
    private void ExitOperation(bool counted, int epoch)
    {
        _operationDepth.Value--;
        ExitOperationOnThread();

        TakenAnchor? taken = null;
        bool logOutLeftBehind = false;
        ILogger logger;
        lock (_lock)
        {
            // The last operation of its epoch: a first login waiting for it looks again.
            if (--_operationsByEpoch[epoch] == 0)
            {
                _operationsByEpoch.Remove(epoch);
                _operationsEnded?.TrySetResult();
                _operationsEnded = null;
            }
            if (!counted)
                return;

            _activeOperations--;
            if (_activeOperations == 0)
            {
                if (_pendingLogout is { } generation)
                {
                    _pendingLogout = null;
                    taken = TakeAnchorForLogoutLocked(generation);
                    SignalIfNoLogoutLocked();
                }
                logOutLeftBehind = _leftBehindLogoutPending;
                _leftBehindLogoutPending = false;
            }
            logger = _logger;
        }

        if (taken is { } logout)
            LogOut(logout, logger);
        if (logOutLeftBehind)
            UnderTransitionOrPost(LogOutLeftBehind);
    }

    /// <summary>The count an operation takes on the record; given back once, on the thread that took it.</summary>
    private sealed class OperationLease(TokenLoginRecord record, bool counted, int epoch, int thread) : IDisposable
    {
        private int _released;

        // A lease given back on another thread would unbalance the per-thread operation depth and stamp the next
        // operation with a stale login: that is a bug in the library, refused loudly rather than absorbed.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3877:Exceptions should not be thrown from unexpected methods",
            Justification = "Disposal on a foreign thread is an internal invariant violation, never caller-reachable.")]
        public void Dispose()
        {
            if (Environment.CurrentManagedThreadId != thread)
            {
                throw new InvalidOperationException(
                    "An operation's count on the token's gate must be given back on the thread that took it.");
            }
            if (Interlocked.Exchange(ref _released, 1) == 0)
                record.ExitOperation(counted, epoch);
        }
    }

    /// <summary>The lease of an operation that counts on no gate (see <see cref="EnterOperation"/>).</summary>
    private sealed class NoOperation : IDisposable
    {
        public static readonly NoOperation Instance = new();

        public void Dispose()
        {
            // Nothing was counted.
        }
    }
}
