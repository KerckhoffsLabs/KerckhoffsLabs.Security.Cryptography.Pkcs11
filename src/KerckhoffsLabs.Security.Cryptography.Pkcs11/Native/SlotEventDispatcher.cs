using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// The slot-event stream of one initialized module, shared by every load of it: the only code that calls
/// <c>C_WaitForSlotEvent</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>C_WaitForSlotEvent</c> consumes the event it returns, and PKCS#11 leaves simultaneous calls from one
/// application undefined, whatever the module's threading mode. So the event stream belongs to the module,
/// not to one <c>Pkcs11Library</c>: at most one call is inside the module at a time, and every event it
/// returns goes to every subscriber (one per <c>Pkcs11Library</c>).
/// </para>
/// <para>
/// A subscriber keeps the events it has not taken yet as a set of slot ids, in arrival order. Two events
/// in one slot merge: an event only says that something changed in that slot, and the caller has to read
/// the slot again to learn what, so nothing is lost, and the set never holds more ids than the module has
/// slots.
/// </para>
/// <para>
/// A blocking wait runs on a background thread, the pump, started by the first waiter and stopping once no
/// subscriber waits. It calls through any subscriber's library, so it outlives the one that started it.
/// While it runs, a poll takes what its subscriber has without calling the module. Otherwise a poll calls
/// <c>C_WaitForSlotEvent</c> with <c>CKF_DONT_BLOCK</c> itself, one at a time. Disposing a subscriber ends
/// its waits at once. The pump's own call ends with the next event, or with the <c>C_Finalize</c> that
/// follows the last load's dispose.
/// </para>
/// </remarks>
internal sealed class SlotEventDispatcher
{
    // Guards every field below, and every subscription's state. Monitor, not Lock: polls wait on it.
    private readonly object _gate = new();
    private readonly List<SlotEventSubscription> _subscribers = [];

    // A poll is inside the module. Nothing else calls it meanwhile.
    private bool _polling;

    // The pump thread is running, or about to: polls do not call the module.
    private bool _pumping;

    private int _queuedPolls;

    /// <summary>Polls waiting for another poll to leave the module (test seam).</summary>
    internal int QueuedPolls
    {
        get
        {
            lock (_gate)
                return _queuedPolls;
        }
    }

    /// <summary>Subscribes <paramref name="library"/>: from now on it receives every event of the module.</summary>
    public SlotEventSubscription Subscribe(LowLevelPkcs11Library library)
    {
        var subscription = new SlotEventSubscription(this, library);
        lock (_gate)
            _subscribers.Add(subscription);
        return subscription;
    }

    /// <summary>Ends <paramref name="subscription"/>: its waits throw <see cref="ObjectDisposedException"/>.</summary>
    internal void Unsubscribe(SlotEventSubscription subscription)
    {
        TaskCompletionSource<ulong>[] orphaned;
        lock (_gate)
        {
            if (!_subscribers.Remove(subscription))
                return;
            orphaned = subscription.CloseLocked();
        }
        foreach (TaskCompletionSource<ulong> waiter in orphaned)
            waiter.TrySetException(new ObjectDisposedException(nameof(Pkcs11Library)));
    }

    /// <summary>Takes a pending event for <paramref name="subscription"/>, polling the module if nothing else is.</summary>
    internal bool TryTake(SlotEventSubscription subscription, out ulong slotId)
    {
        lock (_gate)
        {
            while (true)
            {
                subscription.ThrowIfClosedLocked();
                if (subscription.TryTakeLocked(out slotId))
                    return true;
                if (_pumping)
                    return false; // the pump will see any event; nothing may call the module beside it
                if (!_polling)
                    break;

                _queuedPolls++;
                try
                {
                    Monitor.Wait(_gate);
                }
                finally
                {
                    _queuedPolls--;
                }
            }
            _polling = true;
        }

        CKR rv;
        ulong polled;
        try
        {
            (rv, polled) = Call(subscription.LibraryOrThrow, CKF.CKF_DONT_BLOCK);
        }
        finally
        {
            lock (_gate)
            {
                _polling = false;
                Monitor.PulseAll(_gate);
            }
        }

        if (rv == CKR.CKR_NO_EVENT)
        {
            slotId = 0;
            return false;
        }
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpWaitForSlotEvent);

        lock (_gate)
        {
            PublishLocked(polled);
            subscription.ThrowIfClosedLocked();
            return subscription.TryTakeLocked(out slotId);
        }
    }

    /// <summary>Waits for the next event for <paramref name="subscription"/>, starting the pump if none runs.</summary>
    internal Task<ulong> WaitAsync(SlotEventSubscription subscription, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        TaskCompletionSource<ulong> waiter;
        bool startPump;
        lock (_gate)
        {
            subscription.ThrowIfClosedLocked();
            if (subscription.TryTakeLocked(out ulong pending))
                return Task.FromResult(pending);

            waiter = new TaskCompletionSource<ulong>(TaskCreationOptions.RunContinuationsAsynchronously);
            subscription.AddWaiterLocked(waiter);
            startPump = !_pumping;
            _pumping = true;
        }

        if (startPump)
            new Thread(Pump) { IsBackground = true, Name = "PKCS#11 slot events" }.Start();

        if (cancellationToken.CanBeCanceled)
        {
            CancellationTokenRegistration registration = cancellationToken.UnsafeRegister(
                static (state, token) =>
                {
                    var (dispatcher, subscription, waiter) =
                        ((SlotEventDispatcher, SlotEventSubscription, TaskCompletionSource<ulong>))state!;
                    lock (dispatcher._gate)
                        subscription.RemoveWaiterLocked(waiter);
                    waiter.TrySetCanceled(token);
                },
                (this, subscription, waiter));
            _ = waiter.Task.ContinueWith(
                static (_, state) => ((CancellationTokenRegistration)state!).Dispose(),
                registration, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        return waiter.Task;
    }

    // The pump: blocking waits, one at a time, while any subscriber waits.
    private void Pump()
    {
        lock (_gate)
        {
            while (_polling)
                Monitor.Wait(_gate);
        }

        while (true)
        {
            LowLevelPkcs11Library? library;
            lock (_gate)
            {
                library = _subscribers.Exists(s => s.HasWaitersLocked) ? AnyLibraryLocked() : null;
                if (library is null)
                {
                    _pumping = false;
                    Monitor.PulseAll(_gate);
                    return;
                }
            }

            CKR rv;
            ulong slotId;
            try
            {
                (rv, slotId) = Call(library, 0);
            }
            catch (ObjectDisposedException)
            {
                continue; // that library was disposed since it was picked, and has unsubscribed: pick another
            }
            catch (Exception e)
            {
                Stop(e);
                return;
            }

            if (rv != CKR.CKR_OK)
            {
                // A blocking call returns an event or an error, never CKR_NO_EVENT: that is an error too.
                // CKR_CRYPTOKI_NOT_INITIALIZED is C_Finalize waking the wait: every load was disposed.
                Stop(Pkcs11Exception.Create(rv, Pkcs11Operations.OpWaitForSlotEvent));
                return;
            }
            lock (_gate)
                PublishLocked(slotId);
        }
    }

    // Ends the pump, failing every wait with what ended it. The next wait starts a new pump.
    private void Stop(Exception error)
    {
        List<TaskCompletionSource<ulong>> failed = [];
        lock (_gate)
        {
            _pumping = false;
            foreach (SlotEventSubscription subscription in _subscribers)
                failed.AddRange(subscription.TakeWaitersLocked());
            Monitor.PulseAll(_gate);
        }
        foreach (TaskCompletionSource<ulong> waiter in failed)
            waiter.TrySetException(error);
    }

    // A library that is still alive, to call the module through; drops the subscribers of libraries
    // collected without Dispose.
    private LowLevelPkcs11Library? AnyLibraryLocked()
    {
        for (int i = 0; i < _subscribers.Count; i++)
        {
            if (_subscribers[i].Library is { } library)
                return library;

            // Collected, so nothing can be awaiting it any more; end it all the same.
            foreach (TaskCompletionSource<ulong> orphan in _subscribers[i].CloseLocked())
                orphan.TrySetException(new ObjectDisposedException(nameof(Pkcs11Library)));
            _subscribers.RemoveAt(i--);
        }
        return null;
    }

    private void PublishLocked(ulong slotId)
    {
        foreach (SlotEventSubscription subscription in _subscribers)
            subscription.DeliverLocked(slotId);
    }

    private static (CKR ReturnValue, ulong SlotId) Call(LowLevelPkcs11Library library, ulong flags)
    {
        CKR rv = library.C_WaitForSlotEvent((NativeCULong)flags, out NativeCULong slotId, IntPtr.Zero);
        return (rv, (ulong)slotId);
    }
}

/// <summary>
/// One <c>Pkcs11Library</c>'s view of its module's slot events: those it has not taken yet, and the
/// threads waiting for one. Its state is guarded by its dispatcher's lock (the <c>Locked</c> members).
/// </summary>
/// <remarks>
/// It holds its library weakly. The dispatcher is reachable from the module registry for as long as the
/// module is loaded, so a strong reference would keep a library abandoned without <c>Dispose</c> alive,
/// and with it a load that never stops needing the module, which then is never finalized.
/// </remarks>
internal sealed class SlotEventSubscription : IDisposable
{
    private readonly SlotEventDispatcher _dispatcher;
    private readonly WeakReference<LowLevelPkcs11Library> _library;
    private readonly List<ulong> _pending = [];
    private readonly LinkedList<TaskCompletionSource<ulong>> _waiters = [];
    private bool _closed;

    internal SlotEventSubscription(SlotEventDispatcher dispatcher, LowLevelPkcs11Library library)
    {
        _dispatcher = dispatcher;
        _library = new WeakReference<LowLevelPkcs11Library>(library);
    }

    /// <summary>The library this subscriber calls the module through; <see langword="null"/> once collected.</summary>
    internal LowLevelPkcs11Library? Library => _library.TryGetTarget(out LowLevelPkcs11Library? library) ? library : null;

    /// <summary><see cref="Library"/>, for a caller that holds it, and so knows it is alive.</summary>
    internal LowLevelPkcs11Library LibraryOrThrow => Library ?? throw new ObjectDisposedException(nameof(Pkcs11Library));

    /// <summary>Takes a pending event, polling the module if nothing else is calling it.</summary>
    public bool TryTake(out ulong slotId) => _dispatcher.TryTake(this, out slotId);

    /// <summary>Waits for the next event; several threads waiting take one event each, in turn.</summary>
    public Task<ulong> WaitAsync(CancellationToken cancellationToken) => _dispatcher.WaitAsync(this, cancellationToken);

    /// <summary>Unsubscribes: pending waits throw <see cref="ObjectDisposedException"/>.</summary>
    public void Dispose() => _dispatcher.Unsubscribe(this);

    internal bool HasWaitersLocked => _waiters.Count > 0;

    internal void ThrowIfClosedLocked() => ObjectDisposedException.ThrowIf(_closed, this);

    internal bool TryTakeLocked(out ulong slotId)
    {
        if (_pending.Count == 0)
        {
            slotId = 0;
            return false;
        }
        slotId = _pending[0];
        _pending.RemoveAt(0);
        return true;
    }

    internal void AddWaiterLocked(TaskCompletionSource<ulong> waiter) => _waiters.AddLast(waiter);

    internal void RemoveWaiterLocked(TaskCompletionSource<ulong> waiter) => _waiters.Remove(waiter);

    // The oldest waiter takes the event; with none, it waits in the pending set, merged with any event
    // of the same slot already there.
    internal void DeliverLocked(ulong slotId)
    {
        if (_closed)
            return;
        if (_waiters.First is { } first)
        {
            _waiters.RemoveFirst();
            first.Value.TrySetResult(slotId);
        }
        else if (!_pending.Contains(slotId))
        {
            _pending.Add(slotId);
        }
    }

    internal TaskCompletionSource<ulong>[] TakeWaitersLocked()
    {
        TaskCompletionSource<ulong>[] waiters = [.. _waiters];
        _waiters.Clear();
        return waiters;
    }

    internal TaskCompletionSource<ulong>[] CloseLocked()
    {
        _closed = true;
        _pending.Clear();
        return TakeWaitersLocked();
    }
}
