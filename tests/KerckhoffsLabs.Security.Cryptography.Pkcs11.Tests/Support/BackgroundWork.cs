namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Work run on a thread of its own, for a test that blocks one thread while another goes on: a
/// <see cref="TaskCreationOptions.LongRunning"/> task on the default scheduler, which gets a dedicated background
/// thread, never a pool thread a blocked test could starve.
/// </summary>
/// <remarks>
/// The task keeps whatever the work throws, so the test reads it from <see cref="Failure"/> on its own thread
/// instead of catching everything on the worker's. Every wait is bounded by the caller (<see cref="Join"/>), so a
/// deadlock shows as a timeout, not a hung run.
/// </remarks>
internal sealed class BackgroundWork
{
    private readonly Task _task;
    private Thread? _thread;

    public BackgroundWork(Action work)
    {
        _task = new Task(() =>
        {
            Volatile.Write(ref _thread, Thread.CurrentThread);
            work();
        }, TaskCreationOptions.LongRunning);
    }

    /// <summary>Creates the work and starts it at once.</summary>
    public static BackgroundWork Run(Action work)
    {
        var started = new BackgroundWork(work);
        started.Start();
        return started;
    }

    /// <summary>Starts the work, once.</summary>
    public void Start() => _task.Start(TaskScheduler.Default);

    /// <summary>Whether the work has started and not yet finished, as <see cref="Thread.IsAlive"/>.</summary>
    public bool IsAlive => _task.Status is not (TaskStatus.Created or TaskStatus.RanToCompletion or TaskStatus.Faulted
        or TaskStatus.Canceled);

    /// <summary>Waits at most <paramref name="timeout"/> for the work to finish; whether it did.</summary>
    public bool Join(TimeSpan timeout) => ((IAsyncResult)_task).AsyncWaitHandle.WaitOne(timeout);

    /// <summary>
    /// Waits at most <paramref name="timeout"/> for the work to block (its thread in a wait, a lock or a sleep) while it
    /// still runs; whether it did. A negative check without a timing guess: the work is seen waiting, not merely slow.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The thread must be seen waiting without a break for <see cref="Settle"/>: a thread passes through brief waits
    /// on its way (a contended lock taken at once, the sleep phase of a spin-wait), and one of those seen once would
    /// report it blocked before it reached the wait under test.
    /// </para>
    /// <para>
    /// It cannot tell which wait the thread is in (it reads <see cref="Thread.ThreadState"/>, a debugging aid): a test
    /// that uses it to show the work did not get past a point also asserts what happens once the wait is released, so
    /// a thread stuck elsewhere fails there. It never passes a test the work finished or failed: those are checked
    /// first. Prefer a hook the code under test runs at the wait (as <c>TokenLoginRecord.WhileHoldingTransition</c>)
    /// where there is one.
    /// </para>
    /// </remarks>
    public bool WaitUntilBlocked(TimeSpan timeout)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        TimeSpan? blockedSince = null;
        while (clock.Elapsed < timeout && !_task.IsCompleted)
        {
            Thread? thread = Volatile.Read(ref _thread);
            bool waiting = thread is not null && (thread.ThreadState & ThreadState.WaitSleepJoin) != 0;
            if (!waiting)
                blockedSince = null;
            else if (blockedSince is null)
                blockedSince = clock.Elapsed;
            else if (clock.Elapsed - blockedSince.Value >= Settle)
                return IsAlive;
            Thread.Sleep(1);
        }
        return false;
    }

    /// <summary>How long <see cref="WaitUntilBlocked"/> must see the thread waiting without a break.</summary>
    public static TimeSpan Settle { get; } = TimeSpan.FromMilliseconds(100);

    /// <summary>What the work threw, or <see langword="null"/> while it runs or once it returned.</summary>
    public Exception? Failure => _task.Exception?.InnerException;
}
