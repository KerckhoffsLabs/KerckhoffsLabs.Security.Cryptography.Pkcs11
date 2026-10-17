using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// <see cref="ServerProcess"/> with an ordinary child (<c>env</c>, <c>cmd.exe</c>) instead of the BouncyHsm
/// server, so its environment and Windows handle handling are checked on every CI leg, including the
/// ones that do not build BouncyHsm.
/// </summary>
[NoBackendCollection("Starts ordinary child processes and loads no PKCS#11 module, so it shares no native state " +
                     "with any backend collection.")]
public sealed partial class ServerProcessTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    // BouncyHsmServer.ServerEnvironment removes a developer's own BouncyHsm_* settings by mapping them to
    // null; this is where that removal has to reach the child.
    [Fact]
    public void Start_RemovesAVariableMappedToNullAndSetsTheOthers()
    {
        string removed = $"KL_SP_REMOVED_{Guid.NewGuid():N}";
        string added = $"KL_SP_ADDED_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(removed, "inherited");
        try
        {
            var lines = new ConcurrentQueue<string>();
            (string fileName, string[] arguments) = OperatingSystem.IsWindows()
                ? (Path.Join(Environment.SystemDirectory, "cmd.exe"), new[] { "/c", "set" })
                : ("/usr/bin/env", Array.Empty<string>());
            using var process = ServerProcess.Start(fileName, arguments, Path.GetTempPath(),
                new Dictionary<string, string?> { [removed] = null, [added] = "value" }, lines.Enqueue);

            Assert.True(SpinWait.SpinUntil(() => process.HasExited, Timeout), "the child did not exit");
            process.WaitForOutput();

            Assert.Contains($"{added}=value", lines);
            Assert.DoesNotContain(lines, line => line.StartsWith(removed + "=", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(lines, line => line.StartsWith("PATH=", StringComparison.OrdinalIgnoreCase)); // the rest is inherited
        }
        finally { Environment.SetEnvironmentVariable(removed, null); }
    }

    /// <summary>
    /// The handle list <see cref="ServerProcess"/> passes to <c>CreateProcessW</c>: a child must not inherit the
    /// test host's inheritable handles, or a file SoftHSM opened could not be deleted while the child runs.
    /// </summary>
    [Fact]
    public void Start_OnWindows_DoesNotInheritTheTestHostsOpenHandles()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Handle inheritance into a child process is a Windows behaviour.");
        string path = Path.Join(Path.GetTempPath(), $"sp-inherit-{Guid.NewGuid():N}.tmp");
        ServerProcess process;
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            Assert.True(SetHandleInformation(file.SafeFileHandle, HandleFlagInherit, HandleFlagInherit),
                $"SetHandleInformation failed: {Marshal.GetLastPInvokeError()}");
            process = ServerProcess.Start(Path.Join(Environment.SystemDirectory, "cmd.exe"),
                ["/c", "ping -n 30 127.0.0.1"], Path.GetTempPath(), new Dictionary<string, string?>(), _ => { });
        }
        using (process)
        {
            try
            {
                Assert.False(process.HasExited, "the child exited before the check");
                // Our handle is closed; the delete fails with a sharing violation only if the child holds one.
                var ex = Record.Exception(() => File.Delete(path));
                Assert.True(ex is null, $"The child inherited the test host's handle to {path}: {ex?.Message}");
            }
            finally { process.Kill(Timeout); }
        }
    }

    private const uint HandleFlagInherit = 0x1;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetHandleInformation(Microsoft.Win32.SafeHandles.SafeFileHandle handle, uint mask, uint flags);
}
