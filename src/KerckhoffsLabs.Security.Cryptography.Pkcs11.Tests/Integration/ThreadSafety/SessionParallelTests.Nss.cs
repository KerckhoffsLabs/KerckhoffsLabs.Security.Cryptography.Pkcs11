using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// Real cross-session concurrency against NSS softoken. pkcs11-mock allows one open session at a
/// time, so <see cref="SessionParallelTests"/> can only take turns; NSS's generic token allows many,
/// needs no login, and keeps every session object in one slot-wide hash shared by all sessions —
/// so these cases put genuinely concurrent sessions on the same object table.
/// </summary>
/// <remarks>
/// Since 3.130, softoken removes session objects under the slot lock (Bug 2061391) and turns bad
/// session/object reference counts and key-object double frees into a process abort (Bug 2072682).
/// A wrapper lifecycle bug that closes a session twice, or destroys or touches an object through a
/// session that is already gone, therefore takes the test host down here rather than passing
/// silently, which makes this backend a stricter lifetime check than the mock. Workers run as tasks on
/// threads of their own, so what one throws reaches the test, with its cause, instead of ending the
/// process.
/// </remarks>
[Collection("Nss")]
public sealed class SessionParallelTests_Nss(NssBackendFixture backend)
{
    private const int ThreadCount = 8;

    // Typed as the interface: OpenWorkspace is its default method, and picks the no-login path NSS needs.
    private readonly IPkcs11Backend _backend = backend;

    /// <summary>
    /// Each thread owns a workspace and repeatedly generates, finds, inspects and destroys its own
    /// labelled session key while the others do the same. Every key must be found exactly once by
    /// its owner and be gone after its destroy — concurrent sessions must neither lose nor leak
    /// objects in the shared table.
    /// </summary>
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ParallelSessions_GenerateFindAndDestroyOwnKeys()
    {
        const int iterations = 25;

        RunTogether(ThreadCount, (t, start) =>
        {
            using var workspace = _backend.OpenWorkspace();
            start.ArriveAndWait();

            for (int i = 0; i < iterations; i++)
            {
                string label = $"par-{t}-{i}-{Guid.NewGuid():N}";
                using (var key = workspace.GenerateAesKey(bitLength: 256, label: label))
                using (var attrs = key.GetAttributeValue(CKA.CKA_VALUE_LEN))
                {
                    Assert.Equal(32UL, Assert.Single(attrs).GetValueAsUlong());
                }

                using var filter = ObjectTemplate.Empty().Label(label).Build();
                using (var found = workspace.FindKeys(filter))
                {
                    Assert.Single(found).Destroy();
                }

                using var after = workspace.FindKeys(filter);
                Assert.Empty(after);
            }
        });
    }

    /// <summary>
    /// Half the threads open a workspace, create session keys and close it without destroying them,
    /// over and over; the other half keep one workspace open and search for, and read attributes of,
    /// those same keys. Closing a session frees its objects (PKCS#11 v3.2 §5.6, <c>C_CloseSession</c>),
    /// so the searchers race object removal by design: a key that vanishes between find and read may
    /// fail with <see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/>, and nothing else is acceptable. Once all
    /// threads are done, no key created by a closer may still be visible.
    /// </summary>
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind()
    {
        const int rounds = 20;
        const int keysPerRound = 4;
        const int closers = ThreadCount / 2;

        string run = Guid.NewGuid().ToString("N");
        string[] labels = [.. Enumerable.Range(0, closers * keysPerRound).Select(n => $"close-{run}-{n}")];
        int closersRunning = closers;

        RunTogether(ThreadCount, (t, start) =>
        {
            if (t < closers)
            {
                start.ArriveAndWait();
                try
                {
                    for (int r = 0; r < rounds; r++)
                    {
                        using var workspace = _backend.OpenWorkspace();
                        for (int k = 0; k < keysPerRound; k++)
                        {
                            // Deliberately not destroyed: the workspace's close must free it.
                            using var key = workspace.GenerateAesKey(label: labels[(t * keysPerRound) + k]);
                        }
                    }
                }
                finally
                {
                    Interlocked.Decrement(ref closersRunning);
                }
                return;
            }

            using var searcher = _backend.OpenWorkspace();
            start.ArriveAndWait();
            int next = t;
            while (Volatile.Read(ref closersRunning) > 0)
            {
                using var filter = ObjectTemplate.Empty().Label(labels[next++ % labels.Length]).Build();
                try
                {
                    using var found = searcher.FindKeys(filter);
                    foreach (var attrs in found.Select(key => key.GetAttributeValue(CKA.CKA_VALUE_LEN)))
                        attrs.Dispose();
                }
                catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_OBJECT_HANDLE_INVALID)
                {
                    // The owning session closed between the find and the read — the race under test.
                }
            }
        });

        using var check = _backend.OpenWorkspace();
        foreach (ObjectTemplate filter in labels.Select(label => ObjectTemplate.Empty().Label(label).Build()))
        {
            using (filter)
            using (var leftover = check.FindKeys(filter))
                Assert.Empty(leftover);
        }
    }

    /// <summary>
    /// Disposing a workspace while another thread is mid-call on it must wait for that call and then
    /// close the native session exactly once. The worker may see its call succeed, be refused by the
    /// busy guard while <c>Dispose</c> holds the session (<see cref="InvalidOperationException"/>),
    /// or find the workspace already disposed (<see cref="ObjectDisposedException"/>); a
    /// <see cref="Pkcs11Exception"/> would mean a native call reached a closed session handle.
    /// </summary>
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public async Task Dispose_RacingInFlightCallsOnTheSameWorkspace_NeverReachesAClosedSession()
    {
        const int rounds = 50;

        for (int r = 0; r < rounds; r++)
        {
            var workspace = _backend.OpenWorkspace();
            var key = workspace.GenerateAesKey();

            using var started = new ManualResetEventSlim(false);
            Task worker = OnItsOwnThread(() =>
            {
                started.Set();
                try
                {
                    while (true)
                    {
                        _ = workspace.GenerateRandom(32);
                        using var attrs = key.GetAttributeValue(CKA.CKA_VALUE_LEN);
                    }
                }
                catch (ObjectDisposedException)
                {
                    // Expected end of the loop: the workspace was disposed between calls.
                }
                catch (InvalidOperationException ex) when (ex.Message.Contains("Concurrent access", StringComparison.Ordinal))
                {
                    // Expected: the busy guard refused a call while Dispose held the session.
                }
            });

            started.Wait(TestContext.Current.CancellationToken);
            Thread.Yield();
            workspace.Dispose();

            // Anything else the worker threw, a Pkcs11Exception from a closed session included, fails here.
            await worker;
            key.Dispose();
        }
    }

    /// <summary>
    /// Runs <paramref name="body"/> on <paramref name="count"/> threads of their own, handing each its index
    /// and a start gate that releases them together once their setup is done, then fails with every
    /// worker's exception once all of them have finished.
    /// </summary>
    private static void RunTogether(int count, Action<int, StartGate.Participant> body)
    {
        using var gate = new StartGate(count);
        Task[] workers =
        [
            .. Enumerable.Range(0, count).Select(index => OnItsOwnThread(() =>
            {
                using StartGate.Participant participant = gate.Join();
                body(index, participant);
            })),
        ];

        // Throws an AggregateException holding what every failed worker threw.
        Task.WaitAll(workers, TestContext.Current.CancellationToken);
    }

    // A dedicated thread, so the workers really run at once, and a task so that what one throws reaches
    // the test instead of ending the process.
    private static Task OnItsOwnThread(Action action)
        => Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    /// <summary>Holds every participant until all of them have arrived, or given up.</summary>
    private sealed class StartGate(int participants) : IDisposable
    {
        private readonly CountdownEvent _arrivals = new(participants);

        public Participant Join() => new(this);

        public void Dispose() => _arrivals.Dispose();

        public sealed class Participant(StartGate gate) : IDisposable
        {
            private int _arrived;

            /// <summary>Counts this participant in, then waits for every other one.</summary>
            public void ArriveAndWait()
            {
                Arrive();
                gate._arrivals.Wait(TestContext.Current.CancellationToken);
            }

            // A participant that fails before arriving still counts as arrived, so it cannot hold the
            // others at the gate forever.
            public void Dispose() => Arrive();

            private void Arrive()
            {
                if (Interlocked.Exchange(ref _arrived, 1) == 0)
                    gate._arrivals.Signal();
            }
        }
    }
}
