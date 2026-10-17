using System.Collections.Concurrent;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// <see cref="ServerProcess"/> with an ordinary child (<c>env</c>) instead of the BouncyHsm server, so its
/// environment handling is checked without a BouncyHsm build. Linux only, like the BouncyHsm backend.
/// </summary>
[NoBackendCollection("Starts an ordinary child process and loads no PKCS#11 module, so it shares no native state " +
                     "with any backend collection.")]
public sealed class ServerProcessTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    // BouncyHsmServer.ServerEnvironment removes a developer's own BouncyHsm_* settings by mapping them to
    // null; this is where that removal has to reach the child.
    [Fact]
    public void Start_RemovesAVariableMappedToNullAndSetsTheOthers()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The BouncyHsm backend, and so ServerProcess, is Linux-only.");
        string removed = $"KL_SP_REMOVED_{Guid.NewGuid():N}";
        string added = $"KL_SP_ADDED_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(removed, "inherited");
        try
        {
            var lines = new ConcurrentQueue<string>();
            using var process = ServerProcess.Start("/usr/bin/env", [], Path.GetTempPath(),
                new Dictionary<string, string?> { [removed] = null, [added] = "value" }, lines.Enqueue);

            Assert.True(SpinWait.SpinUntil(() => process.HasExited, Timeout), "the child did not exit");
            process.WaitForOutput();

            Assert.Contains($"{added}=value", lines);
            Assert.DoesNotContain(lines, line => line.StartsWith(removed + "=", StringComparison.Ordinal));
            Assert.Contains(lines, line => line.StartsWith("PATH=", StringComparison.Ordinal)); // the rest is inherited
        }
        finally { Environment.SetEnvironmentVariable(removed, null); }
    }
}
