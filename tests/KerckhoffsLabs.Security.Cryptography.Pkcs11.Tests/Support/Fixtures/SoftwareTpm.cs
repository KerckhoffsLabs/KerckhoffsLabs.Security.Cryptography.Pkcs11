using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// One software TPM 2.0 behind a resource manager, private to its owner, as <see cref="BouncyHsmServer"/>
/// is for BouncyHsm. Three processes, each started once the one before it is ready:
/// <list type="number">
/// <item>swtpm, the TPM, listening on loopback only on a freshly chosen pair of ports (the command port
/// and, one above it, the control port the <c>swtpm</c> TCTI expects), started powered on and past
/// <c>TPM2_Startup</c>.</item>
/// <item>A D-Bus session bus of its own, on a socket in the state directory, so nothing outside it is
/// reached or needed.</item>
/// <item>tpm2-abrmd on that bus, connected to swtpm. A TPM holds only three transient objects and a
/// few sessions at a time; the resource manager swaps them in and out for its clients, as the
/// kernel's <c>/dev/tpmrm0</c> does on a real machine, which tpm2-pkcs11 relies on.</item>
/// </list>
/// The TPM's state and the bus socket live in a fresh temporary directory. Disposing kills the three
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

    /// <summary>The TCTI configuration string a tpm2-tss client needs to reach the TPM through tpm2-abrmd,
    /// with <c>DBUS_SESSION_BUS_ADDRESS</c> set to <see cref="BusAddress"/>.</summary>
    public string Tcti => "tabrmd:bus_type=session";

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
    public static SoftwareTpm Start(string swtpmPath, string dbusDaemonPath, string abrmdPath)
    {
        try
        {
            return StartOnce(swtpmPath, dbusDaemonPath, abrmdPath);
        }
        catch (InvalidOperationException) when (File.Exists(swtpmPath))
        {
            return StartOnce(swtpmPath, dbusDaemonPath, abrmdPath);
        }
    }

    private static SoftwareTpm StartOnce(string swtpmPath, string dbusDaemonPath, string abrmdPath)
    {
        var tpm = new SoftwareTpm(Directory.CreateTempSubdirectory("kl-swtpm-").FullName);
        try
        {
            int port = FreeLoopbackPortPair();
            tpm.StartProcess("swtpm", swtpmPath, SwtpmArguments(tpm._stateDirectory, port), environment: NoEnvironmentChanges,
                isReady: _ => AcceptsConnections(port));

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
                ["--session", "--logger=stdout", "--flush-all", "--max-transients=100", $"--tcti=swtpm:host=127.0.0.1,port={port}"],
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
