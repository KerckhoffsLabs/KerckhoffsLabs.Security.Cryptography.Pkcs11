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
internal sealed class BackgroundWork(Action work)
{
    private readonly Task _task = new(work, TaskCreationOptions.LongRunning);

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

    /// <summary>What the work threw, or <see langword="null"/> while it runs or once it returned.</summary>
    public Exception? Failure => _task.Exception?.InnerException;
}
