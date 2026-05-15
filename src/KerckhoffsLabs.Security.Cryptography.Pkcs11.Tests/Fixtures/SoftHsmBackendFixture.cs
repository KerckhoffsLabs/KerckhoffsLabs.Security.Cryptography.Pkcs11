using System.Diagnostics;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping SoftHSM2. Creates a fresh token directory
/// per test run, initializes a token with a deterministic SO/USER PIN, loads
/// libsofthsm2.so, and exposes the resulting slot through <see cref="IPkcs11Backend"/>.
/// Tests using this fixture must use <see cref="SoftHsmAvailable"/> as a [ConditionalFact]
/// gate to skip when SoftHSM2 isn't installed.
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

    public static bool SoftHsmAvailable =>
        (Settings.SoftHsmLibraryPath is { } p && File.Exists(p)) || SoftHsmDiscover() is not null;

    public SoftHsmBackendFixture()
    {
        string? libPath = Settings.SoftHsmLibraryPath ?? SoftHsmDiscover();
        if (libPath is null)
        {
            // Not available — leave fields in a benign state. Tests gate on SoftHsmAvailable.
            LibraryPath = string.Empty;
            _tokenDir = _configPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        // Use the config that libsofthsm2.so will read at C_Initialize time.
        // The library reads SOFTHSM2_CONF once when the .so is loaded into the
        // process; a temp-dir config set afterwards is invisible to it.
        _configPath = Environment.GetEnvironmentVariable("SOFTHSM2_CONF")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                            ".config", "softhsm2", "softhsm2.conf");

        // Derive tokendir from the config file so we can clean up afterwards.
        _tokenDir = ResolveTokenDir(_configPath);

        // Delete any leftover token with the same label from a previous run.
        RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true);

        // Initialize a fresh token via softhsm2-util.
        RunUtil($"--init-token --free " +
                $"--label \"{TokenLabel}\" " +
                $"--so-pin \"{Settings.SoPin}\" " +
                $"--pin \"{Settings.UserPin}\"");

        Library = new Pkcs11Library(LibraryPath);
        try
        {
            var slots = Library.GetSlotList();
            Pkcs11Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel) ?? throw new InvalidOperationException($"SoftHSM2 token '{TokenLabel}' did not appear in slot list.");
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
        try { Library?.Dispose(); } catch { /* ignore teardown errors */ }
        try { RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true); } catch { }
    }

    private static string? SoftHsmDiscover()
    {
        string[] candidates =
        [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so",
            @"C:\SoftHSM2\lib\softhsm2-x64.dll",
        ];
        return candidates.FirstOrDefault(File.Exists);
    }

    private void RunUtil(string args, bool ignoreFailure = false)
    {
        var psi = new ProcessStartInfo("softhsm2-util", args)
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

    private static string ResolveTokenDir(string configPath)
    {
        if (!File.Exists(configPath)) return string.Empty;
        foreach (var line in File.ReadAllLines(configPath))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("directories.tokendir", StringComparison.OrdinalIgnoreCase))
            {
                var idx = trimmed.IndexOf('=');
                if (idx >= 0) return trimmed[(idx + 1)..].Trim();
            }
        }
        return string.Empty;
    }
}

/// <summary>xUnit collection definition for the SoftHSM2 backend.</summary>
[CollectionDefinition("SoftHsm")]
public sealed class SoftHsmBackendCollection : ICollectionFixture<SoftHsmBackendFixture> { }
