using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping Kryoptic — a fourth, fully independent real PKCS#11
/// implementation (Rust, OpenSSL-backed) alongside SoftHSM2, opencryptoki, and NSS softoken. See
/// BL-028: NSS already covers ChaCha20-Poly1305 and the SP800-108 counter KDF on a real token, but
/// AES-CCM and SLH-DSA still had zero real-backend coverage — Kryoptic 1.5.2 implements both
/// (confirmed via its own <c>C_GetMechanismList</c>: <see cref="CKM.CKM_AES_CCM"/> and
/// <see cref="CKM.CKM_SLH_DSA"/> are both advertised; <c>CKM_CHACHA20_POLY1305</c> is not — Kryoptic
/// 1.5.2 has no ChaCha20 support at all, so that gap remains NSS-only), closing the remaining gap
/// instead of leaving those two families' <c>CK_*_PARAMS</c> marshalling verified only by the
/// in-process <c>ManagedSoftToken</c> fake.
///
/// Uses the library built from the vendor/kryoptic submodule and placed next to the test assembly
/// by the BuildKryoptic MSBuild target; <see cref="Settings.KryopticLibraryPath"/> may override the
/// path for local debugging. Linux-only for now (see build-kryoptic.sh).
///
/// Unlike SoftHSM2 (which needs the external softhsm2-util to create/init a token), Kryoptic
/// implements standard <c>C_InitToken</c>/<c>C_InitPIN</c> directly, so this fixture provisions
/// its token entirely through the library under test — no companion process. Token storage is a
/// SQLite file described by a TOML config (KRYOPTIC_CONF), written next to the library alongside
/// a fresh, empty database so each test run starts from a factory-state token.
/// </summary>
public sealed partial class KryopticBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when Kryoptic is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    // SupportsMlDsa/MlKem/SlhDsa and AeadAuthFailureCode intentionally use IPkcs11Backend's default
    // implementations (the advertised C_GetMechanismList / null): no SoftHSM-style build-marker
    // override is needed because this backend is built with `pqc` on every leg that runs it
    // (see build-kryoptic.sh) — the mechanism list already tells the truth.

    /// <summary>True if the token supports <see cref="CKM.CKM_CHACHA20_POLY1305"/>. Kryoptic 1.5.2
    /// has no ChaCha20 support of any kind (confirmed against its own <c>C_GetMechanismList</c> and
    /// its source, which defines no ChaCha20 mechanism at all) — NSS softoken remains the only real
    /// backend for this mechanism family.</summary>
    public static bool KryopticSupportsChaCha20Poly1305 => false;

    private const int SlotNumber = 0;

    public static bool KryopticAvailable =>
        (Settings.KryopticLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    public KryopticBackendFixture()
    {
        string? libPath = Settings.KryopticLibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        // Config and token store live next to the library, mirroring SoftHsmBackendFixture. A
        // fresh sqlite file each run guarantees factory state without needing a delete/reinit
        // dance through an external tool.
        string nativeDir = Path.GetDirectoryName(libPath)!;
        string configPath = Path.Join(nativeDir, "kryoptic.conf");
        string dbPath = Path.Join(nativeDir, "kryoptic-token.sql");
        try { File.Delete(dbPath); } catch { /* best-effort */ }

        File.WriteAllText(configPath,
            "[[slots]]\n" +
            $"slot = {SlotNumber}\n" +
            "dbtype = \"sqlite\"\n" +
            $"dbargs = \"{dbPath.Replace("\\", "\\\\")}\"\n");

        // libkryoptic_pkcs11.so reads KRYOPTIC_CONF via getenv() at C_Initialize time, same
        // caveat as SoftHSM2_CONF: .NET's Environment.SetEnvironmentVariable does not propagate
        // to native getenv() on Linux, so call setenv() directly too.
        Environment.SetEnvironmentVariable("KRYOPTIC_CONF", configPath);
        SetNativeEnv("KRYOPTIC_CONF", configPath);

        Library = new Pkcs11Library(LibraryPath);
        try
        {
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.SlotId.Value == SlotNumber)
                ?? throw new InvalidOperationException($"Kryoptic slot {SlotNumber} did not appear in the slot list.");

            slot.InitToken(new SecurePin(SoPin.Span), TokenLabel);

            using (Pkcs11Workspace so = Library.OpenWorkspace(TokenLabel, CKU.CKU_SO, new SecurePin(SoPin.Span)))
            {
                so.InitPin(new SecurePin(UserPin.Span));
            }

            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
    }

    // -----------------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------------

    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(asmDir, "runtimes", GetRid(), "native", "libkryoptic_pkcs11.so");
        return File.Exists(candidate) ? candidate : null;
    }

    internal static string GetRid() =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "linux-arm64" : "linux-x64";

    // -----------------------------------------------------------------------
    // libc setenv shim — Environment.SetEnvironmentVariable does not propagate
    // to native getenv() on Linux.
    // -----------------------------------------------------------------------

    [LibraryImport("libc", EntryPoint = "setenv", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LinuxSetEnv(string name, string value, int overwrite);

    internal static void SetNativeEnv(string name, string value)
    {
        int rc = LinuxSetEnv(name, value, 1);
        if (rc != 0)
            throw new InvalidOperationException($"setenv({name}) failed with errno {Marshal.GetLastPInvokeError()}.");
    }
}

/// <summary>xUnit collection definition for the Kryoptic backend.</summary>
[CollectionDefinition("Kryoptic")]
public sealed class KryopticBackendCollection : ICollectionFixture<KryopticBackendFixture>
{ }
