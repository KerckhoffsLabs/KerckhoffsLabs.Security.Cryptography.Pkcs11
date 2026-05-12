using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.ThreadSafety;

[Collection("Mock")]
public sealed class SessionBusyGuardTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void ConcurrentCall_FromDifferentThread_Throws_InvalidOperationException()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var startGate = new System.Threading.ManualResetEventSlim(false);
            using var holdGate = new System.Threading.ManualResetEventSlim(false);

            Exception? capturedB = null;

            // Thread A: take the busy lock via the internal AcquireExclusive helper
            // (accessible via [InternalsVisibleTo]), hold it open via a gate, then release.
            var threadA = new System.Threading.Thread(() =>
            {
                using var lease = session.AcquireExclusive(nameof(ConcurrentCall_FromDifferentThread_Throws_InvalidOperationException));
                startGate.Set();
                holdGate.Wait();
            });

            // Thread B: wait until A holds the lock, then call any public method.
            // The guard should detect cross-thread contention and throw.
            var threadB = new System.Threading.Thread(() =>
            {
                startGate.Wait();
                try
                {
                    session.GetSessionInfo();
                }
                catch (Exception ex)
                {
                    capturedB = ex;
                }
                finally
                {
                    holdGate.Set();
                }
            });

            threadA.Start();
            threadB.Start();
            threadA.Join();
            threadB.Join();

            Assert.NotNull(capturedB);
            Assert.IsType<InvalidOperationException>(capturedB);
            Assert.Contains("Concurrent access", capturedB!.Message);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    [Fact]
    public void ReentrantCall_FromSameThread_Succeeds()
    {
        // Same-thread reentrancy is required by secure helpers (e.g. GenerateAesKey calls
        // public GenerateKey internally). The lock is reentrant on the same thread.
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var outerLease = session.AcquireExclusive(nameof(ReentrantCall_FromSameThread_Succeeds));
            // Same thread — calling a public method that internally re-acquires must succeed.
            _ = session.GetSessionInfo();
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}
