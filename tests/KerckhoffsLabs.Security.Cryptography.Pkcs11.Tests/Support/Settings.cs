using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Per-test-run configuration. All values are environment-driven so
/// developers can point the suite at any PKCS#11 module.
/// </summary>
public static class Settings
{
    /// <summary>
    /// Path to the pkcs11-mock shared library. Falls back to a path next
    /// to the test assembly when the env var is unset.
    /// </summary>
    public static string MockLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_MOCK_LIBRARY")
        ?? DefaultMockPath();

    /// <summary>
    /// Optional path to a SoftHSM2 PKCS#11 library. Tests that require it
    /// skip themselves when this resolves to null.
    /// </summary>
    public static string? SoftHsmLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SOFTHSM_LIBRARY");

    /// <summary>
    /// Normal-user PIN for fixture tokens. Matches the pkcs11-mock default.
    /// Set PKCS11_TEST_USER_PIN to override (e.g. for SoftHSM2).
    /// </summary>
    public static string UserPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_USER_PIN") ?? "11111111";

    /// <summary>
    /// SO PIN for fixture tokens. Matches the pkcs11-mock default.
    /// </summary>
    public static string SoPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SO_PIN") ?? "11111111";

    /// <summary>
    /// Optional path to a system-installed opencryptoki PKCS#11 library — a second, independent real
    /// backend for cross-implementation coverage. Tests skip when this resolves to null; the token is
    /// provisioned out-of-band (by CI), not by the fixture.
    /// </summary>
    public static string? OpenCryptokiLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_LIBRARY");

    /// <summary>Token label of the provisioned opencryptoki token (must match what CI initialized).</summary>
    public static string OpenCryptokiTokenLabel =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_TOKEN") ?? "kl-octk";

    /// <summary>Normal-user PIN for the opencryptoki token.</summary>
    public static string OpenCryptokiUserPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_USER_PIN") ?? "12345678";

    /// <summary>SO PIN for the opencryptoki token (opencryptoki's default is 87654321).</summary>
    public static string OpenCryptokiSoPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_SO_PIN") ?? "87654321";

    /// <summary>
    /// Optional path to a Mozilla NSS softoken PKCS#11 library (<c>libsoftokn3.so</c>) — a third, fully
    /// independent real backend. Tests skip when this resolves to null. NSS softoken exposes a public
    /// "NSS Generic Crypto Services" token that needs no config, database, or PIN, so the fixture opens
    /// it without a login; only session (public) objects are reachable, which suffices for stateless
    /// crypto and session-lifetime keys.
    /// </summary>
    public static string? NssLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_NSS_LIBRARY");

    /// <summary>
    /// Parameter string the NSS fixture passes to <c>C_Initialize</c> in <c>pReserved</c> (see
    /// <see cref="Pkcs11LibraryOptions.ModuleParameters"/>). NSS softoken before 3.52 refuses to
    /// initialize without one; later releases accept it too. The default opens no certificate or key
    /// database — the same configuration later releases fall back to when given none — so only the
    /// "NSS Generic Crypto Services" token the tests use is reachable.
    /// </summary>
    public static string NssModuleParameters =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_NSS_PARAMETERS")
        ?? "configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen,optimizeSpace";

    /// <summary>Token label of NSS softoken's login-not-required crypto services token.</summary>
    public static string NssTokenLabel =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_NSS_TOKEN") ?? "NSS Generic Crypto Services";

    /// <summary>
    /// Optional path to a Kryoptic PKCS#11 library — a fourth, fully independent real backend.
    /// Falls back to the path the BuildKryoptic MSBuild target places next to the
    /// test assembly. Tests that require it skip themselves when this resolves to null.
    /// </summary>
    public static string? KryopticLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_KRYOPTIC_LIBRARY");

    /// <summary>
    /// Directory holding a BouncyHsm build (<c>server/BouncyHsm.dll</c> plus
    /// <c>runtimes/&lt;rid&gt;/native/</c>). Falls back to the <c>bouncyhsm</c> directory the
    /// BuildBouncyHsm MSBuild target stages next to the test assembly.
    /// </summary>
    public static string BouncyHsmDirectory =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_BOUNCYHSM_DIR")
        ?? Path.Join(AppContext.BaseDirectory, "bouncyhsm");

    /// <summary>Label of the token the BouncyHsm fixture creates on its private server.</summary>
    public static string BouncyHsmTokenLabel =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_BOUNCYHSM_TOKEN") ?? "kl-bouncyhsm";

    /// <summary>
    /// Optional path to a Craton HSM PKCS#11 library (craton-hsm-core) — another fully independent
    /// real backend. Falls back to the path the BuildCratonHsm MSBuild target places next to the
    /// test assembly. Tests that require it skip themselves when this resolves to null.
    /// </summary>
    public static string? CratonHsmLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_CRATON_HSM_LIBRARY");

    /// <summary>
    /// Path to the tpm2-pkcs11 PKCS#11 library, set by the tpm2-pkcs11 image
    /// (build/tpm2-pkcs11/Dockerfile) the tests run in. Unset elsewhere, and its tests skip.
    /// </summary>
    public static string? Tpm2Pkcs11LibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_TPM2_PKCS11_LIBRARY");

    /// <summary>
    /// Path to the swtpm program the tpm2-pkcs11 fixture starts its software TPM with, set by the
    /// same image. Unset elsewhere, and the tpm2-pkcs11 tests skip.
    /// </summary>
    public static string? SwtpmPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SWTPM");

    /// <summary>
    /// Path to wolfTPM's firmware TPM server (fwtpm_server), the second software TPM the tpm2-pkcs11
    /// fixture can run tpm2-pkcs11 over, set by the same image. Used when <see cref="Tpm2SoftwareTpm"/> is
    /// <c>fwtpm</c>.
    /// </summary>
    public static string? FwtpmPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_FWTPM");

    /// <summary>
    /// Path to the TCG's TPM 2.0 reference implementation, built as a simulator (tpm2-simulator), the third
    /// software TPM the tpm2-pkcs11 fixture can run tpm2-pkcs11 over, set by the same image. Used when
    /// <see cref="Tpm2SoftwareTpm"/> is <c>tcgtpm</c>.
    /// </summary>
    public static string? TcgTpmPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_TCGTPM");

    /// <summary>
    /// Path to IBM's TPM 2.0 simulator (ibmswtpm2's tpm_server), the fourth software TPM the tpm2-pkcs11
    /// fixture can run tpm2-pkcs11 over, set by the same image. Used when <see cref="Tpm2SoftwareTpm"/> is
    /// <c>ibmtpm</c>.
    /// </summary>
    public static string? IbmTpmPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_IBMTPM");

    /// <summary>
    /// Which tpm2-pkcs11 store backend the tpm2-pkcs11 fixture uses: <c>esysdb</c> (its SQLite store, the
    /// default) or <c>fapi</c> (tpm2-tss's FAPI keystore, provisioned by the fixture on its TPM).
    /// </summary>
    public static string Tpm2Pkcs11Backend =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_TPM2_BACKEND") is { Length: > 0 } backend ? backend : "esysdb";

    /// <summary>The FAPI profile directory for the <c>fapi</c> backend, set by the tpm2-pkcs11 image.</summary>
    public static string? FapiProfileDirectory =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_FAPI_PROFILES");

    /// <summary>
    /// Which software TPM the tpm2-pkcs11 fixture runs: <c>swtpm</c> (libtpms, the default), <c>swtpm-fips</c>
    /// (swtpm restricted as on a FIPS host), <c>swtpm-min</c> (swtpm with the fewest algorithms), <c>fwtpm</c>
    /// (wolfTPM's firmware TPM), <c>tcgtpm</c> (the TCG reference implementation) or <c>ibmtpm</c> (IBM's
    /// simulator). CI runs the suite over each.
    /// </summary>
    public static string Tpm2SoftwareTpm =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_TPM") is { Length: > 0 } tpm ? tpm : "swtpm";

    /// <summary>
    /// Path to tpm2-abrmd, the TPM resource manager the tpm2-pkcs11 fixture puts in front of swtpm, set by
    /// the same image. Unset elsewhere, and the tpm2-pkcs11 tests skip.
    /// </summary>
    public static string? Tpm2AbrmdPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_TPM2_ABRMD");

    /// <summary>
    /// Path to dbus-daemon, which the tpm2-pkcs11 fixture runs the private session bus tpm2-abrmd is on
    /// with, set by the same image. Unset elsewhere, and the tpm2-pkcs11 tests skip.
    /// </summary>
    public static string? DbusDaemonPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_DBUS_DAEMON");

    private static string DefaultMockPath()
    {
        string baseDir = AppContext.BaseDirectory;

        // Every platform keys off the PROCESS architecture (the testhost), not the OS: a 32-bit
        // run on a 64-bit Windows OS (WOW64) or an x64 process under Rosetta on Arm64 macOS would
        // otherwise resolve the wrong-architecture mock and fail to load it (BadImageFormat).
        // Matches SoftHsmBackendFixture.GetRid, reused by the other real-backend fixtures.
        Architecture arch = RuntimeInformation.ProcessArchitecture;
        string rid =
            OperatingSystem.IsWindows()
                ? arch switch
                {
                    Architecture.X86 => "win-x86",
                    Architecture.Arm64 => "win-arm64",
                    _ => "win-x64",
                }
            : OperatingSystem.IsMacOS()
                ? (arch == Architecture.Arm64 ? "osx-arm64" : "osx-x64")
            : arch == Architecture.Arm64 ? "linux-arm64"
            : "linux-x64";

        string fileName =
            OperatingSystem.IsWindows() ? "pkcs11-mock.dll" :
            OperatingSystem.IsMacOS() ? "pkcs11-mock.dylib"
            : "pkcs11-mock.so";

        return Path.Join(baseDir, "runtimes", rid, "native", fileName);
    }
}
