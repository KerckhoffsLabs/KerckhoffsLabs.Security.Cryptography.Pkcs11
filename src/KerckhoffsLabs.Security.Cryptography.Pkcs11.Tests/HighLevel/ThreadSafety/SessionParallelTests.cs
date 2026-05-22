using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.ThreadSafety;

[Collection("Mock")]
public sealed class SessionParallelTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    /// <summary>
    /// Verifies that the per-Session busy-guard leaves no stale state after use.
    /// pkcs11-mock supports exactly one open session at a time, so threads take turns
    /// owning the single mock session. Each iteration creates a fresh Session object on
    /// its thread, runs opsPerThread operations (all on the same thread — within-session
    /// re-entry), then closes it. The goal is to confirm that:
    ///   1. The guard exits cleanly after every call (no deadlock or "stuck busy" state).
    ///   2. A newly-opened Session on a different thread starts with a clear guard, so
    ///      successive sessions don't inherit the lock state of their predecessor.
    /// Full cross-session parallelism requires a backend with ulMaxSessionCount > 1
    /// (e.g. SoftHSM2). Against pkcs11-mock we serialise lifecycle while still running
    /// each session lifecycle on a distinct thread to exercise the thread-affinity semantics.
    /// </summary>
    [Fact]
    public void DifferentSessions_OnDifferentThreads_BothSucceed()
    {
        const int threadCount = 8;
        const int opsPerThread = 50;

        // pkcs11-mock: only one session may be open at a time (ulMaxSessionCount = 1 effective).
        // Use a SemaphoreSlim(1) to serialize session open/close while running each lifecycle
        // on a distinct OS thread, exercising thread-affinity of the guard.
        using var sessionSlot = new System.Threading.SemaphoreSlim(1, 1);

        Exception?[] failures = new Exception?[threadCount];
        var threads = new System.Threading.Thread[threadCount];

        for (int t = 0; t < threadCount; t++)
        {
            int threadIndex = t;
            threads[t] = new System.Threading.Thread(() =>
            {
                sessionSlot.Wait();
                try
                {
                    var session = TestKeys.OpenLoggedInSession(_backend);
                    try
                    {
                        for (int i = 0; i < opsPerThread; i++)
                        {
                            // All ops on this thread → same-thread sequential access.
                            // The guard must not be "stuck" from a previous session closed
                            // on a different thread. This validates that guard state scopes
                            // to the Session instance and resets cleanly on dispose.
                            _ = session.GetSessionInfo();
                        }
                    }
                    finally
                    {
                        session.Logout();
                        session.CloseSession();
                    }
                }
                catch (Exception ex)
                {
                    failures[threadIndex] = ex;
                }
                finally
                {
                    sessionSlot.Release();
                }
            });
        }

        foreach (var th in threads) th.Start();
        foreach (var th in threads) th.Join();

        for (int t = 0; t < threadCount; t++)
        {
            Assert.Null(failures[t]);
        }
    }
}
