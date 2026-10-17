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

    private readonly ServerProcess _process;
    private readonly ConcurrentQueue<string> _tail;
    private readonly HttpClient _http;
    private readonly EventHandler _onProcessExit;
    private bool _disposed;

    public int TcpPort { get; }
    public int HttpPort { get; }
    public int ProcessId => _process.Id;
    public IReadOnlyList<string> OutputTail => [.. _tail];

    private BouncyHsmServer(ServerProcess process, ConcurrentQueue<string> tail, int tcpPort, int httpPort)
    {
        _process = process;
        _tail = tail;
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

        var environment = ServerEnvironment(tcpPort, httpPort, Environment.GetEnvironmentVariables(), extraEnvironment);
        string workingDirectory = Path.GetDirectoryName(serverAssemblyPath) is { Length: > 0 } dir && Directory.Exists(dir)
            ? dir : AppContext.BaseDirectory;

        var tail = new ConcurrentQueue<string>();
        var process = ServerProcess.Start(DotnetHost(), [serverAssemblyPath], workingDirectory, environment, line => Record(tail, line));
        var server = new BouncyHsmServer(process, tail, tcpPort, httpPort);
        try
        {
            server.WaitUntilReady(readyTimeout);
            return server;
        }
        catch
        {
            server.Dispose();
            throw;
        }
    }

    // BouncyHsm adds BouncyHsm_-prefixed variables as its last configuration source, above the
    // unprefixed ones and the command line.
    private const string ConfigPrefix = "BouncyHsm_";

    /// <summary>
    /// The environment the server starts with, as changes to the test host's <paramref name="inherited"/>
    /// one (a <see langword="null"/> value removes the variable). The settings go under
    /// <see cref="ConfigPrefix"/>, so nothing inherited outranks them. Inherited <c>BouncyHsm_*</c> and
    /// <c>Kestrel__*</c> variables are removed, since a developer's own BouncyHsm settings could switch on a
    /// persistent store or another endpoint, and the server runs as Production whatever the host's
    /// environment name. <paramref name="extraEnvironment"/> holds configuration keys
    /// (<c>Serilog__MinimumLevel__Default</c>), applied under the same prefix.
    /// </summary>
    internal static Dictionary<string, string?> ServerEnvironment(int tcpPort, int httpPort,
        System.Collections.IDictionary inherited, IReadOnlyDictionary<string, string>? extraEnvironment)
    {
        var environment = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in inherited.Keys.Cast<string>())
        {
            if (name.StartsWith(ConfigPrefix, StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("Kestrel__", StringComparison.OrdinalIgnoreCase))
                environment[name] = null;
        }

        var settings = new Dictionary<string, string>
        {
            ["PersistenceStorageType"] = "InMemory",
            ["BouncyHsmSetup__TcpEndpoint__Endpoint"] = $"127.0.0.1:{tcpPort}",
            ["Kestrel__Endpoints__Http__Url"] = $"http://127.0.0.1:{httpPort}",
            ["BouncyHsmSetup__EnableSwagger"] = "false",
            ["Serilog__MinimumLevel__Default"] = "Warning",
        };
        foreach (var (name, value) in extraEnvironment ?? new Dictionary<string, string>())
            settings[name] = value;
        foreach (var (name, value) in settings)
            environment[ConfigPrefix + name] = value;

        environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        environment["DOTNET_ENVIRONMENT"] = "Production";
        return environment;
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
            throw new InvalidOperationException(RejectionMessage((int)response.StatusCode, response.ReasonPhrase, text, userPin, soPin));
        using var json = JsonDocument.Parse(text);
        return json.RootElement.GetProperty("SlotId").GetInt32();
    }

    /// <summary>
    /// The message for a rejected <c>POST /Slot</c>: its status and the server's reason, never the PINs. The
    /// reason is the ProblemDetails <c>title</c> and <c>detail</c>, read as decoded strings so a PIN the
    /// server escaped (System.Text.Json writes <c>+</c> and non-ASCII as <c>\uXXXX</c>) is still found. A
    /// body that is not JSON is not echoed, since a PIN in it could be encoded any way. The longer PIN is
    /// redacted first, so one holding the other is not half revealed.
    /// </summary>
    internal static string RejectionMessage(int status, string? reasonPhrase, string body, string userPin, string soPin)
    {
        string reason;
        try
        {
            using var json = JsonDocument.Parse(body);
            reason = json.RootElement.ValueKind == JsonValueKind.Object
                ? string.Join(" ", new[] { "title", "detail" }
                    .Select(name => json.RootElement.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null)
                    .Where(text => !string.IsNullOrEmpty(text)))
                : "";
        }
        catch (JsonException)
        {
            reason = $"(a {body.Length}-character body that is not JSON, not shown)";
        }

        foreach (string pin in new[] { userPin, soPin }.Where(pin => pin.Length > 0).OrderByDescending(pin => pin.Length))
            reason = reason.Replace(pin, "***", StringComparison.Ordinal);
        return $"BouncyHsm POST /Slot failed: {status} {reasonPhrase}. {reason}";
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

    private void Kill() => _process.Kill(TimeSpan.FromSeconds(10));

    private static void Record(ConcurrentQueue<string> tail, string line)
    {
        tail.Enqueue(line);
        while (tail.Count > TailLines && tail.TryDequeue(out _)) { }
    }

    private void WaitUntilReady(TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < timeout)
        {
            if (_process.HasExited)
            {
                _process.WaitForOutput();
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
