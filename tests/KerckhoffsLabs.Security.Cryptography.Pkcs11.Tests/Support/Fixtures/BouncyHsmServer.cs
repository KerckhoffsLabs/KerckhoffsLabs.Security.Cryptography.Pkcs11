using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// One BouncyHsm server process, private to its owner: in-memory storage, loopback-only, on two
/// freshly chosen ports. Starting returns only once the REST API answers; disposing kills the
/// process tree. The server's output is drained continuously (so a chatty server never blocks on a
/// full pipe) and its last <see cref="TailLines"/> lines are kept for failure messages.
/// </summary>
internal sealed class BouncyHsmServer : IDisposable
{
    private const int TailLines = 200;
    private static readonly TimeSpan DefaultReadyTimeout = TimeSpan.FromSeconds(60);

    // The server binds JSON property names case-sensitively; with the web default (camelCase) every
    // field arrives unset and it fails with a 500, not a validation 400.
    private static readonly JsonSerializerOptions PascalCase = new() { PropertyNamingPolicy = null };

    private readonly Process _process;
    private readonly ConcurrentQueue<string> _tail = new();
    private readonly HttpClient _http;
    private readonly EventHandler _onProcessExit;
    private bool _disposed;

    public int TcpPort { get; }
    public int HttpPort { get; }
    public int ProcessId => _process.Id;
    public IReadOnlyList<string> OutputTail => [.. _tail];

    private BouncyHsmServer(Process process, int tcpPort, int httpPort)
    {
        _process = process;
        TcpPort = tcpPort;
        HttpPort = httpPort;
        _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{httpPort}/"), Timeout = TimeSpan.FromSeconds(30) };
        _onProcessExit = (_, _) => Kill();
        AppDomain.CurrentDomain.ProcessExit += _onProcessExit;
    }

    /// <summary>
    /// Starts a server from <paramref name="serverAssemblyPath"/> and waits until it is ready. A
    /// failed start is retried once on new ports, since a port can be taken between choosing and binding.
    /// </summary>
    public static BouncyHsmServer Start(string serverAssemblyPath,
        IReadOnlyDictionary<string, string>? extraEnvironment = null, TimeSpan? readyTimeout = null)
    {
        try
        {
            return StartOnce(serverAssemblyPath, extraEnvironment, readyTimeout ?? DefaultReadyTimeout);
        }
        catch (InvalidOperationException) when (File.Exists(serverAssemblyPath))
        {
            return StartOnce(serverAssemblyPath, extraEnvironment, readyTimeout ?? DefaultReadyTimeout);
        }
    }

    private static BouncyHsmServer StartOnce(string serverAssemblyPath,
        IReadOnlyDictionary<string, string>? extraEnvironment, TimeSpan readyTimeout)
    {
        int tcpPort = FreeLoopbackPort();
        int httpPort = FreeLoopbackPort();

        var psi = new ProcessStartInfo(DotnetHost())
        {
            ArgumentList = { serverAssemblyPath },
            WorkingDirectory = Path.GetDirectoryName(serverAssemblyPath) is { Length: > 0 } dir && Directory.Exists(dir)
                ? dir : AppContext.BaseDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["PersistenceStorageType"] = "InMemory";
        psi.Environment["BouncyHsmSetup__TcpEndpoint__Endpoint"] = $"127.0.0.1:{tcpPort}";
        psi.Environment["Kestrel__Endpoints__Http__Url"] = $"http://127.0.0.1:{httpPort}";
        psi.Environment["BouncyHsmSetup__EnableSwagger"] = "false";
        psi.Environment["Serilog__MinimumLevel__Default"] = "Warning";
        foreach (var (name, value) in extraEnvironment ?? new Dictionary<string, string>())
            psi.Environment[name] = value;

        var process = new Process { StartInfo = psi };
        var server = new BouncyHsmServer(process, tcpPort, httpPort);
        process.OutputDataReceived += (_, e) => server.Record(e.Data);
        process.ErrorDataReceived += (_, e) => server.Record(e.Data);
        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            server.WaitUntilReady(readyTimeout);
            return server;
        }
        catch
        {
            server.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a slot holding one token and returns its PKCS#11 slot id. The PINs are sent to the
    /// server and never put into a message: a rejection reports the status and the server's reason only.
    /// </summary>
    public int CreateSlot(string tokenLabel, string userPin, string soPin)
    {
        var body = new
        {
            IsHwDevice = true,
            IsRemovableDevice = false,
            Description = "kl-bouncyhsm",
            Token = new
            {
                Label = tokenLabel,
                SerialNumber = $"kl-{Guid.NewGuid():N}"[..16],
                SimulateHwRng = true,
                SimulateHwMechanism = true,
                SimulateQualifiedArea = false,
                SimulateProtectedAuthPath = false,
                SpeedMode = "WithoutRestriction",
                UserPin = userPin,
                SoPin = soPin,
            },
        };
        using HttpResponseMessage response = _http.PostAsJsonAsync("Slot", body, PascalCase).GetAwaiter().GetResult();
        string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            string reason = text.Replace(userPin, "***", StringComparison.Ordinal).Replace(soPin, "***", StringComparison.Ordinal);
            throw new InvalidOperationException(
                $"BouncyHsm POST /Slot failed: {(int)response.StatusCode} {response.ReasonPhrase}. {reason}");
        }
        using var json = JsonDocument.Parse(text);
        return json.RootElement.GetProperty("SlotId").GetInt32();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _onProcessExit;
        Kill();
        _http.Dispose();
        _process.Dispose();
    }

    private void Kill()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(TimeSpan.FromSeconds(10));
            }
        }
        catch (InvalidOperationException) { /* never started */ }
    }

    private void Record(string? line)
    {
        if (line is null) return;
        _tail.Enqueue(line);
        while (_tail.Count > TailLines && _tail.TryDequeue(out _)) { }
    }

    private void WaitUntilReady(TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < timeout)
        {
            if (_process.HasExited)
            {
                _process.WaitForExit(); // flush the asynchronous output readers
                throw new InvalidOperationException(
                    $"BouncyHsm server exited with code {_process.ExitCode} before it was ready.{Tail()}");
            }
            try
            {
                using HttpResponseMessage r = _http.GetAsync("Slot").GetAwaiter().GetResult();
                if (r.StatusCode == HttpStatusCode.OK) return;
            }
            catch (HttpRequestException) { /* not listening yet */ }
            Thread.Sleep(250);
        }
        throw new InvalidOperationException($"BouncyHsm server was not ready within {timeout}.{Tail()}");
    }

    private string Tail() => _tail.IsEmpty ? "" : Environment.NewLine + string.Join(Environment.NewLine, _tail);

    private static int FreeLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// The dotnet host of this test run, so the server runs on the same .NET install, and arch, as the
    /// test host: DOTNET_HOST_PATH (set by the dotnet CLI), then DOTNET_ROOT, then dotnet on PATH.
    /// </summary>
    private static string DotnetHost()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host))
            return host;
        string exe = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } root && File.Exists(Path.Join(root, exe)))
            return Path.Join(root, exe);
        return exe;
    }
}
