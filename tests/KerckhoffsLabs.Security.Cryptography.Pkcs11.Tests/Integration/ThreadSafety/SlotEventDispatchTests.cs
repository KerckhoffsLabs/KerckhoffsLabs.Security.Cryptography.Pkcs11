using System.Runtime.CompilerServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// Slot events across every <see cref="Pkcs11Library"/> loaded from one module. <c>C_WaitForSlotEvent</c>
/// consumes the event it returns, and PKCS#11 leaves simultaneous calls from one application undefined,
/// so the event stream belongs to the module: one call at a time reaches it, and every library sees every
/// event. The fake module parks a blocking wait until the test raises an event or the module is
/// finalized, and signals each step, so every interleaving is driven by the test, not by timing.
/// </summary>
/// <remarks>
/// <c>realistic</c> makes a second <c>C_Initialize</c> answer <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c>, as
/// a real module does: only the first load then owns the <c>C_Finalize</c>.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class SlotEventDispatchTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    // Disposing the waiting library ends its wait at once, with ObjectDisposedException, even though
    // another load still needs the module and so nothing finalizes it.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DisposingTheWaiter_EndsItsWaitAtOnce_WhileAnotherLoadUsesTheModule(bool realistic)
    {
        using var module = new SlotEventModule(realistic);
        Pkcs11Library waiter = module.Load();
        using Pkcs11Library other = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => waiter.WaitForSlotEvent(Token)), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        waiter.Dispose();

        Assert.IsType<ObjectDisposedException>(await wait.WaitAsync(Generous, Token));
        Assert.Equal(0, module.CallCount("C_Finalize"));
    }

    // Once every load is disposed, the module is finalized exactly once, which wakes the native wait so
    // it leaves the module: in whichever order the loads go, and whether the waiter is the load that
    // initialized the module (and so owns its C_Finalize) or, on a real module, the one that did not.
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, true, false)]
    [InlineData(true, false, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, false, false)]
    public async Task Dispose_OfEveryLoad_FinalizesOnce_AndTheNativeWaitLeaves(
        bool realistic, bool waiterDisposedFirst, bool waiterLoadedFirst)
    {
        using var module = new SlotEventModule(realistic);
        Pkcs11Library first = module.Load();
        Pkcs11Library second = module.Load();
        Pkcs11Library waiter = waiterLoadedFirst ? first : second;
        Pkcs11Library other = waiterLoadedFirst ? second : first;

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => waiter.WaitForSlotEvent(Token)), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        (waiterDisposedFirst ? waiter : other).Dispose();
        Assert.Equal(0, module.CallCount("C_Finalize")); // the other load still needs the module
        (waiterDisposedFirst ? other : waiter).Dispose();

        Assert.IsType<ObjectDisposedException>(await wait.WaitAsync(Generous, Token));
        Assert.True(module.WaitLeft.Wait(Generous, Token), "the native wait never left the module");
        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    // The native wait that was running for a library disposed since must not swallow the event: the
    // library still in use receives it.
    [Fact]
    public async Task EventDuringADisposedWaitersCall_ReachesTheOtherLoad()
    {
        using var module = new SlotEventModule(realistic: true);
        Pkcs11Library waiter = module.Load();
        using Pkcs11Library other = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => waiter.WaitForSlotEvent(Token)), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");
        waiter.Dispose();
        Assert.IsType<ObjectDisposedException>(await wait.WaitAsync(Generous, Token));

        module.RaiseEvent(4);

        Pkcs11Slot slot = await Task.Run(() => other.WaitForSlotEvent(Token), Token).WaitAsync(Generous, Token);
        Assert.Equal(new SlotId(4), slot.SlotId);
    }

    // A poll during a blocking wait is answered without reaching the module, never refused, and the
    // event the wait then receives is seen by every library, the polling one included.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Poll_DuringABlockingWait_IsAnsweredWithoutReachingTheModule(bool sameLoad)
    {
        using var module = new SlotEventModule(realistic: true);
        using Pkcs11Library first = module.Load();
        using Pkcs11Library other = module.Load();
        Pkcs11Library poller = sameLoad ? first : other;

        Task<Pkcs11Slot> wait = Task.Run(() => first.WaitForSlotEvent(Token), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        Assert.False(poller.TryGetSlotEvent(out _));
        Assert.Equal(1, module.CallCount("C_WaitForSlotEvent"));

        module.RaiseEvent(2);
        Assert.Equal(new SlotId(2), (await wait.WaitAsync(Generous, Token)).SlotId);

        // The waiter took the event for `first`; `other` still has it.
        bool pending = poller.TryGetSlotEvent(out Pkcs11Slot? polled);
        Assert.Equal(!sameLoad, pending);
        if (pending)
            Assert.Equal(new SlotId(2), polled!.SlotId);
    }

    // Two blocking waits on two loads share one native wait, and both receive its event.
    [Fact]
    public async Task TwoWaits_OnTwoLoads_ShareOneNativeWait_AndBothGetTheEvent()
    {
        using var module = new SlotEventModule(realistic: true);
        using Pkcs11Library a = module.Load();
        using Pkcs11Library b = module.Load();

        Task<Pkcs11Slot> first = Task.Run(() => a.WaitForSlotEvent(Token), Token);
        Task<Pkcs11Slot> second = Task.Run(() => b.WaitForSlotEvent(Token), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "no wait reached the module");

        module.RaiseEvent(6);

        Assert.Equal(new SlotId(6), (await first.WaitAsync(Generous, Token)).SlotId);
        Assert.Equal(new SlotId(6), (await second.WaitAsync(Generous, Token)).SlotId);
        Assert.Equal(1, module.MaxBlockingInFlight);
    }

    // After the module was finalized, a new load gets its own event stream, even while the wait that
    // C_Finalize woke has not left the module yet: the old stream's end must not reach it.
    [Fact]
    public async Task NewLoad_WhileTheFinalizedWaitIsStillLeaving_GetsItsOwnEvents()
    {
        using var module = new SlotEventModule(realistic: true) { HoldWokenWait = true };
        Pkcs11Library old = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => old.WaitForSlotEvent(Token)), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");
        old.Dispose();
        Assert.IsType<ObjectDisposedException>(await wait.WaitAsync(Generous, Token));
        Assert.True(module.Woken.Wait(Generous, Token), "C_Finalize never woke the wait");

        using Pkcs11Library fresh = module.Load();
        module.RaiseEvent(9);
        Assert.True(fresh.TryGetSlotEvent(out Pkcs11Slot? slot));
        Assert.Equal(new SlotId(9), slot.SlotId);

        module.ReleaseWoken.Set();
        Assert.True(module.WaitLeft.Wait(Generous, Token), "the woken wait never left the module");

        Task<Pkcs11Slot> next = fresh.WaitForSlotEventAsync(Token);
        module.RaiseEvent(10);
        Assert.Equal(new SlotId(10), (await next.WaitAsync(Generous, Token)).SlotId);
    }

    // Polls take turns at the module rather than being refused. The dispatcher's queue count is the
    // signal that the second poll is waiting its turn, so nothing depends on how long a thread takes.
    [Fact]
    public async Task ConcurrentPolls_ReachTheModuleOneAtATime()
    {
        using var module = new SlotEventModule(realistic: true) { ParkFirstPoll = true };
        using Pkcs11Library first = module.Load();
        using Pkcs11Library other = module.Load();

        Task<bool> parked = Task.Run(() => first.TryGetSlotEvent(out _), Token);
        Assert.True(module.PollEntered.Wait(Generous, Token), "the poll never reached the module");

        Task<bool> queued = Task.Run(() => other.TryGetSlotEvent(out _), Token);
        SlotEventDispatcher events = other.LowLevelLibrary!.Module.SlotEvents;
        Assert.True(SpinWait.SpinUntil(() => events.QueuedPolls == 1, Generous), "the second poll never queued");
        Assert.False(queued.IsCompleted);

        module.RaiseEvent(5);
        module.ReleasePoll.Set();

        // The parked poll found no event; the queued one asks the module after it, and finds the new one.
        Assert.False(await parked.WaitAsync(Generous, Token));
        Assert.True(await queued.WaitAsync(Generous, Token));
        Assert.Equal(1, module.MaxPollsInFlight);
        Assert.True(first.TryGetSlotEvent(out Pkcs11Slot? seen)); // the event reached `first` too
        Assert.Equal(new SlotId(5), seen.SlotId);
    }

    // Cancelling one wait ends that wait only: a later one still receives the next event.
    [Fact]
    public async Task CancelledWait_Ends_AndTheNextWaitStillGetsEvents()
    {
        using var module = new SlotEventModule(realistic: true);
        using Pkcs11Library library = module.Load();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(Token);

        Task<Pkcs11Slot> cancelled = library.WaitForSlotEventAsync(cancel.Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled.WaitAsync(Generous, Token));

        Task<Pkcs11Slot> next = library.WaitForSlotEventAsync(Token);
        module.RaiseEvent(3);
        Assert.Equal(new SlotId(3), (await next.WaitAsync(Generous, Token)).SlotId);
        Assert.Equal(1, module.MaxBlockingInFlight);
    }

    // Events in one slot that nobody has taken yet merge into one, so a library that never asks does not
    // pile them up.
    [Fact]
    public async Task UntakenEventsInOneSlot_Merge()
    {
        using var module = new SlotEventModule(realistic: true);
        using Pkcs11Library waiter = module.Load();
        using Pkcs11Library idle = module.Load();

        foreach (ulong raised in (ulong[])[7, 8, 7])
        {
            Task<Pkcs11Slot> wait = waiter.WaitForSlotEventAsync(Token);
            module.RaiseEvent(raised);
            await wait.WaitAsync(Generous, Token);
        }

        Assert.True(idle.TryGetSlotEvent(out Pkcs11Slot? a));
        Assert.True(idle.TryGetSlotEvent(out Pkcs11Slot? b));
        Assert.False(idle.TryGetSlotEvent(out _));
        Assert.Equal(new SlotId(7), a.SlotId);
        Assert.Equal(new SlotId(8), b.SlotId);
    }

    // The module's event stream outlives any one library, so it must not keep a library alive: one
    // abandoned without Dispose still has to be collected, so its module handle's release runs and it
    // stops counting as a load that needs the module.
    [Fact]
    public void AbandonedLibrary_IsNotKeptAliveByTheModulesSlotEvents()
    {
        using var module = new SlotEventModule(realistic: true);
        using Pkcs11Library kept = module.Load();

        WeakReference abandoned = LoadAndAbandon(module);
        for (int i = 0; i < 5 && abandoned.IsAlive; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        Assert.False(abandoned.IsAlive, "the abandoned library's low-level wrapper is still reachable");
        Assert.False(kept.TryGetSlotEvent(out _)); // the stream still works for the library in use
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference LoadAndAbandon(SlotEventModule module) => new(module.Load().LowLevelLibrary);

    /// <summary>
    /// Parks a blocking <c>C_WaitForSlotEvent</c> until <see cref="RaiseEvent"/> or <c>C_Finalize</c>, and
    /// answers a <c>CKF_DONT_BLOCK</c> poll from the events raised. Records how many blocking waits, and
    /// how many polls, are ever inside at once.
    /// </summary>
    private sealed class SlotEventModule(bool realistic) : FakeModule
    {
        private readonly object _gate = new();
        private readonly Queue<ulong> _events = new();
        private bool _initialized;
        private bool _finalized;
        private int _blockingInFlight;
        private int _pollsInFlight;
        private int _polls;

        /// <summary>Set once a blocking wait is inside the module.</summary>
        public ManualResetEventSlim Waiting { get; } = new();

        /// <summary>Set once a blocking wait has left the module.</summary>
        public ManualResetEventSlim WaitLeft { get; } = new();

        /// <summary>Set once <c>C_Finalize</c> has woken a blocking wait.</summary>
        public ManualResetEventSlim Woken { get; } = new();

        /// <summary>With <see cref="HoldWokenWait"/>, lets the woken wait leave.</summary>
        public ManualResetEventSlim ReleaseWoken { get; } = new();

        /// <summary>Keeps a wait that <c>C_Finalize</c> woke inside the module until <see cref="ReleaseWoken"/>.</summary>
        public bool HoldWokenWait { get; init; }

        /// <summary>Keeps the first poll inside the module until <see cref="ReleasePoll"/>; it then finds nothing.</summary>
        public bool ParkFirstPoll { get; init; }

        /// <summary>Set once the first poll is inside the module.</summary>
        public ManualResetEventSlim PollEntered { get; } = new();

        /// <summary>With <see cref="ParkFirstPoll"/>, lets the first poll leave.</summary>
        public ManualResetEventSlim ReleasePoll { get; } = new();

        public int MaxBlockingInFlight { get; private set; }

        public int MaxPollsInFlight { get; private set; }

        public void RaiseEvent(ulong slot)
        {
            lock (_gate)
            {
                _events.Enqueue(slot);
                Monitor.PulseAll(_gate);
            }
        }

        protected override CKR C_Initialize(IntPtr pInitArgs)
        {
            lock (_gate)
            {
                if (realistic && _initialized)
                    return CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED;
                _initialized = true;
                _finalized = false;
                return CKR.CKR_OK;
            }
        }

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            lock (_gate)
            {
                _initialized = false;
                _finalized = true;
                Monitor.PulseAll(_gate);
                return CKR.CKR_OK;
            }
        }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
            => ((ulong)flags & CKF.CKF_DONT_BLOCK) != 0 ? Poll(ref slot) : Block(ref slot);

        private CKR Poll(ref NativeCULong slot)
        {
            lock (_gate)
                MaxPollsInFlight = Math.Max(MaxPollsInFlight, ++_pollsInFlight);
            try
            {
                if (ParkFirstPoll && Interlocked.Increment(ref _polls) == 1)
                {
                    PollEntered.Set();
                    ReleasePoll.Wait(Generous);
                    return CKR.CKR_NO_EVENT;
                }

                lock (_gate)
                {
                    if (_finalized)
                        return CKR.CKR_CRYPTOKI_NOT_INITIALIZED;
                    if (!_events.TryDequeue(out ulong pending))
                        return CKR.CKR_NO_EVENT;
                    slot = (NativeCULong)pending;
                    return CKR.CKR_OK;
                }
            }
            finally
            {
                lock (_gate)
                    _pollsInFlight--;
            }
        }

        private CKR Block(ref NativeCULong slot)
        {
            CKR rv;
            lock (_gate)
            {
                MaxBlockingInFlight = Math.Max(MaxBlockingInFlight, ++_blockingInFlight);
                Waiting.Set();
                while (_events.Count == 0 && !_finalized)
                {
                    if (!Monitor.Wait(_gate, Generous))
                        break;
                }

                if (_events.TryDequeue(out ulong raised))
                {
                    slot = (NativeCULong)raised;
                    rv = CKR.CKR_OK;
                }
                else
                {
                    rv = _finalized ? CKR.CKR_CRYPTOKI_NOT_INITIALIZED : CKR.CKR_GENERAL_ERROR;
                }
                _blockingInFlight--;
            }

            if (rv == CKR.CKR_CRYPTOKI_NOT_INITIALIZED)
            {
                Woken.Set();
                if (HoldWokenWait)
                    ReleaseWoken.Wait(Generous);
            }
            WaitLeft.Set();
            return rv;
        }
    }
}
