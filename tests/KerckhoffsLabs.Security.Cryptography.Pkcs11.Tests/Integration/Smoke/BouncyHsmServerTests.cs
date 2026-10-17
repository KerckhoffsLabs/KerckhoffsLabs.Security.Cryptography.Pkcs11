using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// Lifecycle of the BouncyHsm server process the fixture owns. These start their own servers and
/// never load the PKCS#11 client, so they need no backend collection.
/// </summary>
[NoBackendCollection("Starts private BouncyHsm server processes on their own random ports and never " +
                     "loads the PKCS#11 client, so it shares no native state with the BouncyHsm collection.")]
public sealed partial class BouncyHsmServerTests
{
    private static string ServerDll => BouncyHsmBackendFixture.ServerAssemblyPath()!;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Start_WithMissingServerAssembly_FailsFastWithServerOutput()
    {
        string missing = Path.Join(Path.GetTempPath(), $"no-such-{Guid.NewGuid():N}", "BouncyHsm.dll");
        var sw = Stopwatch.StartNew();

        var ex = Assert.Throws<InvalidOperationException>(() => BouncyHsmServer.Start(missing));

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"took {sw.Elapsed}");
        Assert.Contains("exited", ex.Message, StringComparison.Ordinal);
        Assert.Contains(missing, ex.Message, StringComparison.Ordinal); // the host's own complaint names the path
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Dispose_StopsTheServerProcess()
    {
        var server = BouncyHsmServer.Start(ServerDll);
        int pid = server.ProcessId, tcp = server.TcpPort;

        server.Dispose();

        Assert.Throws<ArgumentException>(() => Process.GetProcessById(pid));
        using var probe = new TcpClient();
        Assert.ThrowsAny<SocketException>(() => probe.Connect("127.0.0.1", tcp));
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CreateSlot_Rejected_MessageNeverContainsThePins()
    {
        using var server = BouncyHsmServer.Start(ServerDll);
        const string userPin = "user-pin-sentinel-4711";
        const string soPin = "so-pin-sentinel-0815";

        // BouncyHsm v2.3.3 validates only the slot's own fields, not the token's: a missing label is
        // the one token input it rejects (a 500, from a null dereference while mapping it).
        var ex = Assert.Throws<InvalidOperationException>(
            () => server.CreateSlot(null!, userPin, soPin));

        Assert.Contains("POST /Slot failed", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(userPin, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(soPin, ex.Message, StringComparison.Ordinal);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public async Task Start_TwiceConcurrently_GivesIndependentServers()
    {
        var starts = await Task.WhenAll(
            Task.Run(() => BouncyHsmServer.Start(ServerDll)),
            Task.Run(() => BouncyHsmServer.Start(ServerDll)));
        using var a = starts[0];
        using var b = starts[1];

        Assert.Equal(4, new HashSet<int> { a.TcpPort, a.HttpPort, b.TcpPort, b.HttpPort }.Count);
        int slotA = a.CreateSlot("kl-a", "11111111", "11111111");
        int slotB = b.CreateSlot("kl-b", "11111111", "11111111");
        Assert.True(slotA > 0 && slotB > 0);
    }

    /// <summary>
    /// On Windows a child created with handle inheritance gets every inheritable handle the test host
    /// has open at that moment, such as SoftHSM's token files (opened with <c>_open</c>, no
    /// <c>_O_NOINHERIT</c>). The server then holds them for its whole life and SoftHSM's
    /// <c>C_DestroyObject</c> fails with <c>CKR_FUNCTION_FAILED</c>, because Windows will not delete a file
    /// another process has open. The server must inherit only its own stdio.
    /// </summary>
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Start_DoesNotInheritTheTestHostsOpenHandles()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Handle inheritance into a child process is a Windows behaviour.");
        string path = Path.Join(Path.GetTempPath(), $"bh-inherit-{Guid.NewGuid():N}.tmp");
        BouncyHsmServer server;
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            Assert.True(SetHandleInformation(file.SafeFileHandle, HandleFlagInherit, HandleFlagInherit),
                $"SetHandleInformation failed: {Marshal.GetLastPInvokeError()}");
            server = BouncyHsmServer.Start(ServerDll);
        }
        using (server)
        {
            // Our handle is closed; the delete fails with a sharing violation only if the server holds one.
            var ex = Record.Exception(() => File.Delete(path));
            Assert.True(ex is null, $"The server inherited the test host's handle to {path}: {ex?.Message}");
        }
    }

    private const uint HandleFlagInherit = 0x1;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetHandleInformation(Microsoft.Win32.SafeHandles.SafeFileHandle handle, uint mask, uint flags);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerboseServer_KeepsRespondingAndOutputTailStaysBounded()
    {
        using var server = BouncyHsmServer.Start(ServerDll, new Dictionary<string, string>
        {
            ["Serilog__MinimumLevel__Default"] = "Verbose",
            ["Serilog__WriteTo__0__Args__restrictedToMinimumLevel"] = "Verbose",
        });

        for (int i = 0; i < 100; i++)
            server.CreateSlot($"kl-verbose-{i}", "11111111", "11111111");

        Assert.InRange(server.OutputTail.Count, 1, 200);
    }
}
