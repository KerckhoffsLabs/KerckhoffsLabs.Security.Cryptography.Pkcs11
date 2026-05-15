using System.Diagnostics;
using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping SoftHSM2. Prefers the library built from
/// the third-party/softhsmv2 submodule (placed next to the test assembly by the
/// BuildSoftHsmV2 MSBuild target); falls back to a system-installed copy when
/// the built artifact is absent.
///
/// Each fixture instance creates an isolated token directory so runs never
/// interfere with the host's SoftHSM2 configuration.
/// </summary>
public sealed class SoftHsmBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = System.Text.Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = System.Text.Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    private readonly string _tokenDir;
    private readonly string _configPath;
    private readonly string _utilPath;

    public static bool SoftHsmAvailable =>
        (Settings.SoftHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null ||
        SystemLibraryPath() is not null;

    public SoftHsmBackendFixture()
    {
        string? libPath = Settings.SoftHsmLibraryPath
            ?? BuiltLibraryPath()
            ?? SystemLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            _tokenDir = _configPath = _utilPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        _utilPath = ResolveUtil(libPath);

        // Always use a fresh isolated token directory so we never touch the
        // host's SoftHSM2 state.
        _tokenDir = Path.Combine(Path.GetTempPath(), "pkcs11net-softhsm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tokenDir);

        _configPath = Path.Combine(_tokenDir, "softhsm2.conf");
        File.WriteAllText(_configPath,
            $"directories.tokendir = {_tokenDir}\n" +
            "objectstore.backend = file\n" +
            "log.level = ERROR\n");

        RunUtil($"--init-token --free " +
                $"--label \"{TokenLabel}\" " +
                $"--so-pin \"{Settings.SoPin}\" " +
                $"--pin \"{Settings.UserPin}\"");

        Library = new Pkcs11Library(LibraryPath);
        try
        {
            var slots = Library.GetSlotList();
            Pkcs11Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"SoftHSM2 token '{TokenLabel}' did not appear in slot list.");
            SlotId = (NativeCULong)found.SlotId;
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { }
        try { if (Directory.Exists(_tokenDir)) Directory.Delete(_tokenDir, recursive: true); } catch { }
    }

    // -----------------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------------

    /// <summary>
    /// Returns the libsofthsm2 built by the BuildSoftHsmV2 MSBuild target,
    /// placed in runtimes/&lt;rid&gt;/native/ next to the test assembly.
    /// </summary>
    private static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string ext = OperatingSystem.IsMacOS() ? "dylib" : "so";
        string rid = GetRid();
        string candidate = Path.Combine(asmDir, "runtimes", rid, "native", $"libsofthsm2.{ext}");
        return File.Exists(candidate) ? candidate : null;
    }

    private static string? SystemLibraryPath()
    {
        string[] candidates =
        [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        ];
        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Resolves softhsm2-util: prefers the one built alongside the library,
    /// then falls back to PATH.
    /// </summary>
    private static string ResolveUtil(string libPath)
    {
        string builtUtil = Path.Combine(Path.GetDirectoryName(libPath)!, "softhsm2-util");
        if (File.Exists(builtUtil)) return builtUtil;
        return "softhsm2-util"; // rely on PATH
    }

    private static string GetRid()
    {
        if (OperatingSystem.IsLinux())
            return System.Runtime.InteropServices.RuntimeInformation.OSArchitecture ==
                   System.Runtime.InteropServices.Architecture.Arm64
                ? "linux-arm64" : "linux-x64";
        if (OperatingSystem.IsMacOS())
            return System.Runtime.InteropServices.RuntimeInformation.OSArchitecture ==
                   System.Runtime.InteropServices.Architecture.Arm64
                ? "osx-arm64" : "osx-x64";
        return "linux-x64";
    }

    // -----------------------------------------------------------------------
    // softhsm2-util runner
    // -----------------------------------------------------------------------

    private void RunUtil(string args, bool ignoreFailure = false)
    {
        var psi = new ProcessStartInfo(_utilPath, args)
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["SOFTHSM2_CONF"] = _configPath;
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start softhsm2-util.");
        string err = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (!ignoreFailure && p.ExitCode != 0)
            throw new InvalidOperationException($"softhsm2-util failed (exit {p.ExitCode}): {err}");
    }
}

/// <summary>xUnit collection definition for the SoftHSM2 backend.</summary>
[CollectionDefinition("SoftHsm")]
public sealed class SoftHsmBackendCollection : ICollectionFixture<SoftHsmBackendFixture> { }
