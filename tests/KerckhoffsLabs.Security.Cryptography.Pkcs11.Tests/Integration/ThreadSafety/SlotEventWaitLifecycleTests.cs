using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// A blocking <c>C_WaitForSlotEvent</c> against the module's lifecycle: two loads of one module, and
/// several callers of one module. The module parks the wait until the test raises an event or the
/// library finalizes it, so every interleaving is driven by the test, not by timing.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SlotEventWaitLifecycleTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(10);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    // Disposing the only load finalizes the module, which wakes the wait. With a second load, that load
    // still needs the module, so it is the last dispose that finalizes, and that must wake the wait too,
    // in whichever order the two are disposed.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Dispose_OfBothLoads_WakesAWaitOnEither(bool waiterDisposedFirst)
    {
        using var module = new WaitingModule();
        Pkcs11Library waiter = module.Load();
        Pkcs11Library other = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => waiter.WaitForSlotEvent()), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        (waiterDisposedFirst ? waiter : other).Dispose();
        Assert.Equal(0, module.CallCount("C_Finalize")); // the other load still uses the module
        (waiterDisposedFirst ? other : waiter).Dispose();

        Exception? outcome = await wait.WaitAsync(Generous, Token);
        var e = Assert.IsType<Pkcs11Exception>(outcome, exactMatch: false);
        Assert.Equal(CKR.CKR_CRYPTOKI_NOT_INITIALIZED, e.ReturnValue);
        Assert.Equal(1, module.CallCount("C_Finalize"));
    }

    // While another load still uses the module, disposing the waiter cannot finalize it, so the wait
    // lasts until an event. That event must not hand back a slot of a library already disposed.
    [Fact]
    public async Task EventAfterTheWaiterWasDisposed_ThrowsObjectDisposed()
    {
        using var module = new WaitingModule();
        Pkcs11Library waiter = module.Load();
        using Pkcs11Library other = module.Load();

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => waiter.WaitForSlotEvent()), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        waiter.Dispose();
        module.RaiseEvent();

        Exception? outcome = await wait.WaitAsync(Generous, Token);
        Assert.IsType<ObjectDisposedException>(outcome);
        Assert.Equal(0, module.CallCount("C_Finalize"));
    }

    // PKCS#11 leaves simultaneous C_WaitForSlotEvent calls from one application undefined, even on a
    // module initialized for concurrent access. A blocking wait therefore excludes every other one, from
    // this library or another load of the module, and a poll alongside it.
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task SecondCall_DuringABlockingWait_IsRefused(bool sameLoad, bool secondBlocks)
    {
        using var module = new WaitingModule();
        using Pkcs11Library first = module.Load();
        using Pkcs11Library other = module.Load();
        Pkcs11Library second = sameLoad ? first : other;

        Task<Exception?> wait = Task.Run(() => Record.Exception(() => first.WaitForSlotEvent()), Token);
        Assert.True(module.Waiting.Wait(Generous, Token), "the wait never reached the module");

        var refused = Assert.Throws<InvalidOperationException>(() =>
        {
            if (secondBlocks)
                second.WaitForSlotEvent();
            else
                second.TryGetSlotEvent(out _);
        });
        Assert.Contains("C_WaitForSlotEvent", refused.Message, StringComparison.Ordinal);
        Assert.Equal(1, module.CallCount("C_WaitForSlotEvent"));

        module.RaiseEvent();
        Assert.Null(await wait.WaitAsync(Generous, Token));

        // The refusal lasts only as long as the wait: once it has returned, the module is free again.
        module.RaiseEvent();
        Assert.True(second.TryGetSlotEvent(out _));
    }

    // Polls take no part in the refusal among themselves: they are serialized, so two of them never
    // reach the module together, and neither is turned away.
    [Fact]
    public async Task ConcurrentPolls_AreSerializedNotRefused()
    {
        using var module = new ParkingPollModule();
        using Pkcs11Library first = module.Load();
        using Pkcs11Library other = module.Load();

        Task<bool> parked = Task.Run(() => first.TryGetSlotEvent(out _), Token);
        Assert.True(module.Entered.Wait(Generous, Token), "the poll never reached the module");

        Task<bool> queued = Task.Run(() => other.TryGetSlotEvent(out _), Token);
        // Give the second poll time to get in if nothing stops it; MaxInFlight below is what decides.
        await Task.WhenAny(queued, Task.Delay(TimeSpan.FromMilliseconds(200), Token));
        Assert.False(queued.IsCompleted, "the second poll reached the module alongside the first");

        module.Release.Set();
        Assert.False(await parked.WaitAsync(Generous, Token));
        Assert.False(await queued.WaitAsync(Generous, Token));
        Assert.Equal(1, module.MaxInFlight);
    }

    /// <summary>Blocks in <c>C_WaitForSlotEvent</c> until an event is raised or <c>C_Finalize</c> arrives.</summary>
    private sealed class WaitingModule : FakeModule
    {
        private readonly ManualResetEventSlim _finalized = new();
        private readonly SemaphoreSlim _events = new(0);

        public ManualResetEventSlim Waiting { get; } = new();

        public void RaiseEvent() => _events.Release();

        protected override CKR C_Finalize(IntPtr pReserved)
        {
            _finalized.Set();
            return CKR.CKR_OK;
        }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
        {
            if (((ulong)flags & CKF.CKF_DONT_BLOCK) != 0)
            {
                if (!_events.Wait(0, Token))
                    return CKR.CKR_NO_EVENT;
                slot = (NativeCULong)1UL;
                return CKR.CKR_OK;
            }

            Waiting.Set();
            int woke = WaitHandle.WaitAny([_events.AvailableWaitHandle, _finalized.WaitHandle], Generous);
            if (woke == 0 && _events.Wait(0, Token))
            {
                slot = (NativeCULong)1UL;
                return CKR.CKR_OK;
            }
            return _finalized.IsSet ? CKR.CKR_CRYPTOKI_NOT_INITIALIZED : CKR.CKR_GENERAL_ERROR;
        }
    }

    /// <summary>Parks the first poll inside the module, and records how many polls are ever inside at once.</summary>
    private sealed class ParkingPollModule : FakeModule
    {
        private int _inFlight;
        private int _calls;

        public ManualResetEventSlim Entered { get; } = new();

        public ManualResetEventSlim Release { get; } = new();

        public int MaxInFlight { get; private set; }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
        {
            int now = Interlocked.Increment(ref _inFlight);
            lock (Release)
                MaxInFlight = Math.Max(MaxInFlight, now);
            if (Interlocked.Increment(ref _calls) == 1)
            {
                Entered.Set();
                Release.Wait(Generous, Token);
            }
            Interlocked.Decrement(ref _inFlight);
            return CKR.CKR_NO_EVENT;
        }
    }
}
