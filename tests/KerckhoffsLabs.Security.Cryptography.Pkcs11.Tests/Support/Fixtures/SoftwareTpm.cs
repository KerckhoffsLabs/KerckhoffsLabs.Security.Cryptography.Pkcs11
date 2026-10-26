using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>The software TPM 2.0 implementations <see cref="SoftwareTpm"/> can run.</summary>
internal enum SoftwareTpmKind
{
    /// <summary>swtpm, over libtpms.</summary>
    Swtpm,

    /// <summary>wolfTPM's firmware TPM (fwtpm_server), over wolfCrypt.</summary>
    Fwtpm,

    /// <summary>The TCG's TPM 2.0 reference implementation (tpm2-simulator), over OpenSSL.</summary>
    TcgReference,
}

/// <summary>
/// One software TPM 2.0, private to its owner, as <see cref="BouncyHsmServer"/> is for BouncyHsm. For
/// swtpm and the TCG reference implementation, three processes, each started once the one before it is
/// ready; for fwtpm_server, the first alone:
/// <list type="number">
/// <item>The TPM, listening on a freshly chosen pair of ports (the command port and, one above it, the
/// control or platform port), past <c>TPM2_Startup</c>: swtpm on loopback only, started powered on and
/// past it; wolfTPM's fwtpm_server, already powered on, which is sent <c>TPM2_Startup(CLEAR)</c>
/// here; or the TCG reference implementation's tpm2-simulator, freshly manufactured, which the
/// <c>mssim</c> TCTI powers on and tpm2-abrmd starts up. The first two take raw TPM commands on the
/// command port, as the <c>swtpm</c> TCTI sends them; tpm2-simulator takes them framed for <c>mssim</c>.</item>
/// <item>For swtpm and tpm2-simulator, a D-Bus session bus of its own, on a socket in the state
/// directory, so nothing outside it is reached or needed.</item>
/// <item>For swtpm and tpm2-simulator, tpm2-abrmd on that bus, connected to it. A TPM holds only three transient objects and a
/// few sessions at a time; the resource manager swaps them in and out for its clients, as the
/// kernel's <c>/dev/tpmrm0</c> does on a real machine, which tpm2-pkcs11 relies on. fwtpm_server can't
/// sit behind one (its <c>TPM2_ContextSave</c> of an object keeps only a reference), so it is reached
/// directly, and is built to hold more objects instead.</item>
/// </list>
/// The TPM's state and the bus socket live in a fresh temporary directory. Disposing kills the
/// processes, last started first, and deletes the directory.
/// </summary>
internal sealed class SoftwareTpm : IDisposable
{
    private const int TailLines = 200;
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(30);
    private static readonly IReadOnlyDictionary<string, string?> NoEnvironmentChanges = new Dictionary<string, string?>();

    private readonly string _stateDirectory;
    private readonly List<(string Name, ServerProcess Process, ConcurrentQueue<string> Tail)> _processes = [];
    private readonly EventHandler _onProcessExit;
    private bool _disposed;

    /// <summary>The D-Bus address of the private session bus tpm2-abrmd is on.</summary>
    public string BusAddress { get; }

    /// <summary>
    /// The TCTI configuration string a tpm2-tss client needs to reach the TPM: through tpm2-abrmd, with
    /// <c>DBUS_SESSION_BUS_ADDRESS</c> set to <see cref="BusAddress"/>; or, for fwtpm_server, directly.
    /// </summary>
    public string Tcti { get; private set; } = "tabrmd:bus_type=session";

    private SoftwareTpm(string stateDirectory)
    {
        _stateDirectory = stateDirectory;
        BusAddress = $"unix:path={Path.Join(stateDirectory, "bus")}";
        _onProcessExit = (_, _) => KillAll();
        AppDomain.CurrentDomain.ProcessExit += _onProcessExit;
    }

    /// <summary>
    /// Starts the three processes and waits until each is ready. A failed start is retried once with a
    /// new state directory and ports, since a port can be taken between choosing and binding.
    /// </summary>
    public static SoftwareTpm Start(SoftwareTpmKind kind, string tpmPath, string dbusDaemonPath, string abrmdPath)
    {
        try
        {
            return StartOnce(kind, tpmPath, dbusDaemonPath, abrmdPath);
        }
        catch (InvalidOperationException) when (File.Exists(tpmPath))
        {
            return StartOnce(kind, tpmPath, dbusDaemonPath, abrmdPath);
        }
    }

    private static SoftwareTpm StartOnce(SoftwareTpmKind kind, string tpmPath, string dbusDaemonPath, string abrmdPath)
    {
        var tpm = new SoftwareTpm(Directory.CreateTempSubdirectory("kl-swtpm-").FullName);
        try
        {
            int port = FreeLoopbackPortPair();
            string tcti;
            if (kind == SoftwareTpmKind.Swtpm)
            {
                tpm.StartProcess("swtpm", tpmPath, SwtpmArguments(tpm._stateDirectory, port), environment: NoEnvironmentChanges,
                    isReady: _ => AcceptsConnections(port));
                tcti = $"swtpm:host=127.0.0.1,port={port}";
            }
            else if (kind == SoftwareTpmKind.TcgReference)
            {
                // tpm2-simulator keeps its NV state in NVChip in its working directory, the state
                // directory, and -m manufactures it afresh.
                tpm.StartProcess("tpm2-simulator", tpmPath, TcgReferenceArguments(port), environment: NoEnvironmentChanges,
                    isReady: _ => AcceptsConnections(port));
                tcti = $"mssim:host=127.0.0.1,port={port}";
            }
            else
            {
                // fwtpm_server keeps its NV state in fwtpm_nv.bin in its working directory, the state
                // directory, so it too starts from a factory-state TPM.
                tpm.StartProcess("fwtpm_server", tpmPath, FwtpmArguments(port), environment: NoEnvironmentChanges,
                    isReady: _ => AcceptsConnections(port));
                SendStartupClear(port);

                // No resource manager: fwtpm_server's TPM2_ContextSave of an object keeps only a reference,
                // which it can't load once the object is flushed, and a resource manager flushes what it
                // saves. Its image build gives it room for tpm2-pkcs11's objects instead.
                tpm.Tcti = $"swtpm:host=127.0.0.1,port={port}";
                return tpm;
            }

            string busSocket = Path.Join(tpm._stateDirectory, "bus");
            tpm.StartProcess("dbus-daemon", dbusDaemonPath,
                ["--session", "--nofork", "--nopidfile", $"--address={tpm.BusAddress}"], environment: NoEnvironmentChanges,
                isReady: _ => File.Exists(busSocket));

            // tpm2-abrmd says it owns its bus name only at the INFO level, which GLib prints only when
            // G_MESSAGES_DEBUG names it. --max-transients=100, its maximum, rather than 27: a C_GenerateKeyPair
            // tpm2-pkcs11 fails after the TPM made the key leaks its two loaded objects, which count against
            // the one connection tpm2-pkcs11 keeps for the whole run, and at the cap every later C_Login
            // fails too, so one failure would fail every test after it.
            tpm.StartProcess("tpm2-abrmd", abrmdPath,
                ["--session", "--logger=stdout", "--flush-all", "--max-transients=100", $"--tcti={tcti}"],
                environment: new Dictionary<string, string?>
                {
                    ["DBUS_SESSION_BUS_ADDRESS"] = tpm.BusAddress,
                    ["G_MESSAGES_DEBUG"] = "all",
                },
                isReady: tail => tail.Any(line => line.Contains("on_name_acquired", StringComparison.Ordinal)));
            return tpm;
        }
        catch
        {
            tpm.Dispose();
            throw;
        }
    }

    // --flags not-need-init,startup-clear: the TPM is powered on and TPM2_Startup(CLEAR) has run, so
    // the first command is accepted. --profile name=custom,remove-disabled=check: the default profile
    // has Camellia and TDES, which an OpenSSL that disables them (Wolfi's, in the image, has neither)
    // makes swtpm refuse to start with; this profile drops whatever OpenSSL refuses, and tpm2-pkcs11
    // uses neither. No --log: swtpm logs nothing by default.
    internal static IReadOnlyList<string> SwtpmArguments(string stateDirectory, int port) =>
    [
        "socket", "--tpm2",
        "--tpmstate", $"dir={stateDirectory}",
        "--server", $"type=tcp,port={port},bindaddr=127.0.0.1",
        "--ctrl", $"type=tcp,port={port + 1},bindaddr=127.0.0.1",
        "--flags", "not-need-init,startup-clear",
        "--profile", "name=custom,remove-disabled=check",
    ];

    // The command port and, one above it, the platform port. fwtpm_server binds every interface; the
    // ports are freshly chosen and the test runs in a container.
    internal static IReadOnlyList<string> FwtpmArguments(int port) =>
    [
        "--port", $"{port}",
        "--platform-port", $"{port + 1}",
    ];

    // The command port, and -m to manufacture the NV state. The platform port is always one above it.
    // tpm2-simulator binds every interface; the ports are freshly chosen and the test runs in a container.
    internal static IReadOnlyList<string> TcgReferenceArguments(int port) => [$"{port}", "-m"];

    // TPM2_Startup(TPM_SU_CLEAR), as a raw command on the command port. TPM_RC_INITIALIZE says the TPM
    // was already started, which is as good.
    private static void SendStartupClear(int port)
    {
        ReadOnlySpan<byte> startup = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        using NetworkStream stream = client.GetStream();
        stream.ReadTimeout = (int)ReadyTimeout.TotalMilliseconds;
        stream.Write(startup);

        byte[] response = new byte[10];
        stream.ReadExactly(response);
        uint rc = (uint)(response[6] << 24 | response[7] << 16 | response[8] << 8 | response[9]);
        if (rc is not (0 or 0x100))
            throw new InvalidOperationException($"fwtpm_server refused TPM2_Startup: TPM_RC 0x{rc:X}.");
    }

    private void StartProcess(string name, string path, IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string?> environment, Func<IReadOnlyCollection<string>, bool> isReady)
    {
        var tail = new ConcurrentQueue<string>();
        var process = ServerProcess.Start(path, arguments, _stateDirectory, environment, line => Record(tail, line));
        _processes.Add((name, process, tail));

        var clock = Stopwatch.StartNew();
        while (!isReady(tail))
        {
            if (process.HasExited)
            {
                process.WaitForOutput();
                throw new InvalidOperationException(
                    $"{name} exited with code {process.ExitCode} before it was ready.{Environment.NewLine}{string.Join(Environment.NewLine, tail)}");
            }
            if (clock.Elapsed > ReadyTimeout)
            {
                throw new InvalidOperationException(
                    $"{name} was not ready within {ReadyTimeout}.{Environment.NewLine}{string.Join(Environment.NewLine, tail)}");
            }
            Thread.Sleep(50);
        }
    }

    private static bool AcceptsConnections(int port)
    {
        try
        {
            using var probe = new TcpClient();
            probe.Connect(IPAddress.Loopback, port);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static void Record(ConcurrentQueue<string> tail, string line)
    {
        tail.Enqueue(line);
        while (tail.Count > TailLines && tail.TryDequeue(out _)) { }
    }

    // Two adjacent free ports: the swtpm TCTI always puts the control channel at port + 1. A port is
    // free if it can be bound; another process can still take it before swtpm does, which Start's
    // single retry covers.
    private static int FreeLoopbackPortPair()
    {
        for (int attempt = 0; attempt < 100; attempt++)
        {
            using var first = new TcpListener(IPAddress.Loopback, 0);
            first.Start();
            int port = ((IPEndPoint)first.LocalEndpoint).Port;
            if (port == IPEndPoint.MaxPort)
                continue;

            try
            {
                using var second = new TcpListener(IPAddress.Loopback, port + 1);
                second.Start();
                return port;
            }
            catch (SocketException)
            {
                // port + 1 is taken; try another pair.
            }
        }

        throw new InvalidOperationException("No two adjacent free loopback ports were found for swtpm.");
    }

    // Last started first: tpm2-abrmd, then the bus it is on, then the TPM it talks to.
    private void KillAll()
    {
        for (int i = _processes.Count - 1; i >= 0; i--)
        {
            try
            {
                _processes[i].Process.Kill(TimeSpan.FromSeconds(5));
            }
            catch (InvalidOperationException)
            {
                // Already gone.
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _onProcessExit;
        KillAll();
        foreach (var (_, process, _) in _processes)
            process.Dispose();
        try
        {
            Directory.Delete(_stateDirectory, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: it is a temporary directory.
        }
    }
}
