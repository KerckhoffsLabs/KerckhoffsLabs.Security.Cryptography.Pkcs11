using System.Diagnostics;
using System.Reflection;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Backend fixture over a pkcs11-gate spec-version shim (build/pkcs11-gate.c) wrapping the
/// vendored SoftHSM2: the gate restricts which PKCS#11 API version the wrapper can negotiate
/// (v2.40 exports only, or a v3.0-truncated interface table) while every operation in the
/// function table still lands in real SoftHSM crypto. This is what lets CI validate the
/// "single managed surface across v2.40 / v3.0 / v3.2 modules" promise end to end.
/// </summary>
/// <remarks>
/// <para>
/// The gate dlopens its target from an env var, and the target is a private file COPY of
/// libsofthsm2 — a distinct path/inode loads a second, independent instance with its own
/// <c>C_Initialize</c> state, config, and token store, so the gate never contends with the
/// main <see cref="SoftHsmBackendFixture"/>'s instance.
/// </para>
/// <para>
/// SOFTHSM2_CONF and the gate-target env vars are process-global and read by native code at
/// <c>C_Initialize</c> / first-call time, so these fixtures MUST live in the same xUnit
/// collection as the SoftHSM fixture ("SoftHsm"): collection serialization makes the
/// set-env-then-initialize sequences in each fixture constructor race-free.
/// </para>
/// </remarks>
public abstract class SoftHsmGateBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; }
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    // Same physical SoftHSM build underneath, so the same capability gates apply.
    public bool SupportsMlDsa => SoftHsmBackendFixture.SoftHsmSupportsMlDsa;
    public bool SupportsMlKem => SoftHsmBackendFixture.SoftHsmSupportsMlKem;
    public bool SupportsSlhDsa => SoftHsmBackendFixture.SoftHsmSupportsSlhDsa;
    public CKR? AeadAuthFailureCode => CKR.CKR_ENCRYPTED_DATA_INVALID;

    private readonly string _gateDir;
    private readonly string _configPath;
    private readonly string _utilPath;
    private readonly string _targetCopyPath;

    /// <summary>True when the gate shim for <paramref name="level"/> and SoftHSM are both built.</summary>
    internal static bool GateAvailable(string level)
        => GateLibraryPath(level) is not null && SoftHsmBackendFixture.SoftHsmAvailable;

    private protected SoftHsmGateBackendFixture(string level, string targetEnvVar)
    {
        TokenLabel = $"gate{level}-token";

        string? gatePath = GateLibraryPath(level);
        string? softHsmPath = Settings.SoftHsmLibraryPath ?? SoftHsmBackendFixture.BuiltLibraryPath();
        if (gatePath is null || softHsmPath is null)
        {
            LibraryPath = _gateDir = _configPath = _utilPath = _targetCopyPath = string.Empty;
            return; // unavailable — tests skip via their ConditionalFact gate
        }

        LibraryPath = gatePath;
        _utilPath = SoftHsmBackendFixture.ResolveUtil(softHsmPath);

        // Private copy of libsofthsm2: dlopen of a distinct path/inode yields an independent
        // native instance, so the gate's C_Initialize state and token store never collide with
        // the main SoftHSM fixture's.
        _gateDir = Path.Combine(Path.GetDirectoryName(gatePath)!, $"gate{level}");
        Directory.CreateDirectory(_gateDir);
        _targetCopyPath = Path.Combine(_gateDir, Path.GetFileName(softHsmPath));
        File.Copy(softHsmPath, _targetCopyPath, overwrite: true);

        string tokenStoreDir = Path.Combine(_gateDir, "tokens");
        Directory.CreateDirectory(tokenStoreDir);
        _configPath = Path.Combine(_gateDir, "softhsm2.conf");
        File.WriteAllText(_configPath,
            $"directories.tokendir = {tokenStoreDir}\n" +
            "objectstore.backend = file\n" +
            "log.level = ERROR\n");

        RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true);
        RunUtil($"--init-token --free " +
                $"--label \"{TokenLabel}\" " +
                $"--so-pin \"{Settings.SoPin}\" " +
                $"--pin \"{Settings.UserPin}\"");

        // Both read by native code (SOFTHSM2_CONF at the copy's C_Initialize; the target path at
        // the gate's first bootstrap call), so set them via setenv() before loading. Serialized
        // against the sibling SoftHSM fixtures by the shared "SoftHsm" collection.
        Environment.SetEnvironmentVariable("SOFTHSM2_CONF", _configPath);
        SoftHsmBackendFixture.SetNativeEnv("SOFTHSM2_CONF", _configPath);
        Environment.SetEnvironmentVariable(targetEnvVar, _targetCopyPath);
        SoftHsmBackendFixture.SetNativeEnv(targetEnvVar, _targetCopyPath);

        Library = new Pkcs11Library(gatePath);
        try
        {
            var slots = Library.GetSlotList();
            Pkcs11Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"Gate token '{TokenLabel}' did not appear in slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
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
        if (_gateDir.Length == 0) return;
        try { RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true); } catch { }
        try { Directory.Delete(_gateDir, recursive: true); } catch { }
    }

    private static string? GateLibraryPath(string level)
    {
        if (OperatingSystem.IsWindows()) return null; // gate shims are Linux/macOS only
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Combine(
            asmDir, "runtimes", SoftHsmBackendFixture.GetRid(), "native", $"pkcs11-gate{level}.so");
        return File.Exists(candidate) ? candidate : null;
    }

    // softhsm2-util against the private copy + the gate's own config (passed via the child's
    // environment, so this never depends on the process-global SOFTHSM2_CONF value).
    private void RunUtil(string args, bool ignoreFailure = false)
    {
        var psi = new ProcessStartInfo(_utilPath, $"{args} --module \"{_targetCopyPath}\"")
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

/// <summary>Gate fixture at level 2.40: the module exports only <c>C_GetFunctionList</c>.</summary>
public sealed class SoftHsmGate240Fixture : SoftHsmGateBackendFixture
{
    public SoftHsmGate240Fixture() : base("240", "PKCS11_GATE240_TARGET") { }
    public static bool Available => GateAvailable("240");
}

/// <summary>Gate fixture at level 3.0: <c>C_GetInterface</c> serves a v3.0-truncated,
/// version-rewritten copy of the target's interface table.</summary>
public sealed class SoftHsmGate30Fixture : SoftHsmGateBackendFixture
{
    public SoftHsmGate30Fixture() : base("30", "PKCS11_GATE30_TARGET") { }
    public static bool Available => GateAvailable("30");
}
