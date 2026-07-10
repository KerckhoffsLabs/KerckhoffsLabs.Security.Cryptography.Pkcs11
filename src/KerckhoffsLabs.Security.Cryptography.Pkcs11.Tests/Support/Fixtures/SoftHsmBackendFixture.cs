using System.Diagnostics;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping SoftHSM2. Uses the library built from the
/// vendor/softhsmv2 submodule and placed next to the test assembly by the
/// BuildSoftHsmV2 MSBuild target; <see cref="Settings.SoftHsmLibraryPath"/>
/// may override the path for one-off local debugging. Auto-discovery of a
/// system-installed SoftHSM2 is deliberately not supported — the version that
/// ships in distro packages is unpredictable and prior bugs traced back to
/// mismatched system installs.
///
/// The config and token store are written next to the library so the
/// baked-in DEFAULT_SOFTHSM2_CONF path is satisfied without requiring the
/// SOFTHSM2_CONF environment variable.
/// </summary>
public sealed partial class SoftHsmBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when SoftHSM is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    // PQC capability is gated by the build marker, not the advertised mechanism list: a SoftHSM build
    // can list a PQC mechanism without a working operation path (it depends on the OpenSSL it links).
    /// <inheritdoc/>
    public bool SupportsMlDsa => SoftHsmSupportsMlDsa;
    /// <inheritdoc/>
    public bool SupportsMlKem => SoftHsmSupportsMlKem;
    /// <inheritdoc/>
    public bool SupportsSlhDsa => SoftHsmSupportsSlhDsa;

    /// <inheritdoc/>
    // SoftHSM returns CKR_ENCRYPTED_DATA_INVALID for an AEAD tag-verification failure; pin it so the
    // authenticity tests assert the exact code rather than just "some Pkcs11Exception".
    public CKR? AeadAuthFailureCode => CKR.CKR_ENCRYPTED_DATA_INVALID;

    // === SoftHSM 2.7 capability gates ======================================
    // These are static so they can be passed to [ConditionalFact(nameof(...))],
    // which is evaluated before any fixture instance exists. They encode the
    // capability gaps of the SoftHSM build we ship in vendor/softhsmv2 — when
    // we move to a newer SoftHSM or a real HSM, flip the relevant flag.
    //
    // Real-token coverage gap: AES-CCM, ChaCha20-Poly1305, SP800-108 counter KDF,
    // and SLH-DSA are NOT implemented by either CI real backend — SoftHSM (these flags) nor opencryptoki
    // (see [[project_opencryptoki_soft_token_matrix]]: its soft token also lacks all four). Their
    // parameter marshalling is therefore exercised in CI only by the in-process ManagedSoftToken fake
    // (the *.Managed.cs tests), which implements each over the BCL primitive. To keep that path honest
    // the managed KATs pin a published vector where one is compact (AES-CCM: RFC 3610 #1;
    // ChaCha20-Poly1305: RFC 8439 §2.8.2) and otherwise cross-check against the BCL computed *outside*
    // the marshalling path (SP800-108: CAVP vectors are variable-format ACVP JSON; SLH-DSA: FIPS 205
    // signatures are ~17 KB+). Lighting these up on a real token requires a backend that implements them.

    /// <summary>True if the token supports <see cref="CKM.CKM_CHACHA20_POLY1305"/>.
    /// SoftHSM 2.7 omits the entire ChaCha20 family.</summary>
    public static bool SoftHsmSupportsChaCha20Poly1305 => false;

    /// <summary>True if the token supports the <see cref="CKK.CKK_CHACHA20"/> key type.
    /// Same root cause as <see cref="SoftHsmSupportsChaCha20Poly1305"/>.</summary>
    public static bool SoftHsmSupportsChaCha20KeyType => false;

    /// <summary>True if the token supports <see cref="CKM.CKM_AES_CCM"/>.
    /// SoftHSM 2.7 omits AES-CCM entirely.</summary>
    public static bool SoftHsmSupportsAesCcm => false;

    /// <summary>True if the token accepts SHA-256 (and modern hashes) as the OAEP <c>hashAlg</c>.
    /// Older SoftHSM hardcoded <c>hashAlg == CKM_SHA_1</c> in <c>SoftHSM.cpp:MechParamCheckRSAPKCSOAEP</c>;
    /// upstream #833 (vendored commit de25233) added configurable OAEP parameters, lifting that limit.</summary>
    public static bool SoftHsmSupportsOaepSha256 => true;

    /// <summary>True if the token accepts an ECDH1 KDF other than <c>CKD_NULL</c>.
    /// SoftHSM 2.7 hardcodes <c>kdf == CKD_NULL</c>; see <c>SoftHSM.cpp:deriveECDH</c>.</summary>
    public static bool SoftHsmSupportsEcdh1WithKdf => false;

    /// <summary>True if the SoftHSM build we load actually has ML-DSA (FIPS 204) compiled in
    /// (<see cref="CKM.CKM_ML_DSA_KEY_PAIR_GEN"/> / <see cref="CKM.CKM_ML_DSA"/>). ML-DSA only
    /// compiles in when SoftHSM is built against OpenSSL 3.5+; <c>build-softhsmv2.sh</c> records
    /// that as a marker file next to the library, so this gate reflects the real capability of the
    /// loaded build — true on an OpenSSL-3.5 CI build, false on a system-OpenSSL-3.0 local build.</summary>
    public static bool SoftHsmSupportsMlDsa
    {
        get
        {
            string? lib = Settings.SoftHsmLibraryPath ?? BuiltLibraryPath();
            return lib is not null
                && File.Exists(Path.Combine(Path.GetDirectoryName(lib)!, "softhsm-mldsa.enabled"));
        }
    }

    /// <summary>True if the SoftHSM build we load has ML-KEM (FIPS 203) compiled in
    /// (<see cref="CKM.CKM_ML_KEM_KEY_PAIR_GEN"/> / <see cref="CKM.CKM_ML_KEM"/>). Like ML-DSA, ML-KEM
    /// only compiles in against OpenSSL 3.5+; reflects a <c>softhsm-mlkem.enabled</c> marker next to
    /// the library, kept symmetric with <see cref="SoftHsmSupportsMlDsa"/>.</summary>
    public static bool SoftHsmSupportsMlKem
    {
        get
        {
            string? lib = Settings.SoftHsmLibraryPath ?? BuiltLibraryPath();
            return lib is not null
                && File.Exists(Path.Combine(Path.GetDirectoryName(lib)!, "softhsm-mlkem.enabled"));
        }
    }

    /// <summary>True if the SoftHSM build we load has SLH-DSA (FIPS 205) compiled in
    /// (<see cref="CKM.CKM_SLH_DSA_KEY_PAIR_GEN"/> / <see cref="CKM.CKM_SLH_DSA"/>). Upstream SoftHSM
    /// has no SLH-DSA support today, so this is effectively always false; the gate is kept symmetric
    /// with <see cref="SoftHsmSupportsMlDsa"/> and reflects a <c>softhsm-slhdsa.enabled</c> marker
    /// next to the library, so SLH-DSA tests light up automatically against a future capable build.</summary>
    public static bool SoftHsmSupportsSlhDsa
    {
        get
        {
            string? lib = Settings.SoftHsmLibraryPath ?? BuiltLibraryPath();
            return lib is not null
                && File.Exists(Path.Combine(Path.GetDirectoryName(lib)!, "softhsm-slhdsa.enabled"));
        }
    }

    // Parent directory that SoftHSM2 creates UUID token subdirs inside.
    private readonly string _tokenStoreDir;
    private readonly string _configPath;
    private readonly string _utilPath;

    public static bool SoftHsmAvailable =>
        (Settings.SoftHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    public SoftHsmBackendFixture()
    {
        string? libPath = Settings.SoftHsmLibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            _tokenStoreDir = _configPath = _utilPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        _utilPath = ResolveUtil(libPath);

        // Write config next to the library so the baked-in DEFAULT_SOFTHSM2_CONF
        // is satisfied. SoftHSM2 creates UUID subdirs inside _tokenStoreDir.
        string nativeDir = Path.GetDirectoryName(libPath)!;
        _configPath = Path.Combine(nativeDir, "softhsm2.conf");
        _tokenStoreDir = Path.Combine(nativeDir, "tokens");
        Directory.CreateDirectory(_tokenStoreDir);

        File.WriteAllText(_configPath,
            $"directories.tokendir = {_tokenStoreDir}\n" +
            "objectstore.backend = file\n" +
            "log.level = ERROR\n");

        // Remove any leftover token with the same label from a previous run.
        RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true);

        RunUtil($"--init-token --free " +
                $"--label \"{TokenLabel}\" " +
                $"--so-pin \"{Settings.SoPin}\" " +
                $"--pin \"{Settings.UserPin}\"");

        // libsofthsm2.so reads SOFTHSM2_CONF via getenv() at C_Initialize time.
        // .NET's Environment.SetEnvironmentVariable updates a CLR-internal table on
        // Linux/macOS — it does NOT propagate to libc's getenv(), so we have to
        // call setenv() directly. SetEnvironmentVariable is kept so anything else
        // managed (e.g. softhsm2-util spawned later) sees the same value.
        Environment.SetEnvironmentVariable("SOFTHSM2_CONF", _configPath);
        SetNativeEnv("SOFTHSM2_CONF", _configPath);

        Library = new Pkcs11Library(LibraryPath);
        try
        {
            var slots = Library.GetSlotList();
            Pkcs11Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"SoftHSM2 token '{TokenLabel}' did not appear in slot list.");
            SlotId = (NativeCULong)found.SlotId;
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
        try { RunUtil($"--delete-token --token \"{TokenLabel}\" --force", ignoreFailure: true); } catch { }
        try { if (Directory.Exists(_tokenStoreDir)) Directory.Delete(_tokenStoreDir, recursive: true); } catch { }
    }

    // -----------------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------------

    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        // macOS uses `.so` too: libsofthsm2 is a libtool `-module` bundle (.so), not a .dylib.
        string ext = OperatingSystem.IsWindows() ? "dll" : "so";
        string candidate = Path.Combine(asmDir, "runtimes", GetRid(), "native", $"libsofthsm2.{ext}");
        return File.Exists(candidate) ? candidate : null;
    }

    internal static string ResolveUtil(string libPath)
    {
        string utilName = OperatingSystem.IsWindows() ? "softhsm2-util.exe" : "softhsm2-util";
        string builtUtil = Path.Combine(Path.GetDirectoryName(libPath)!, utilName);
        if (!File.Exists(builtUtil))
            throw new FileNotFoundException(
                $"{utilName} not found next to the built libsofthsm2 at '{builtUtil}'. " +
                "The BuildSoftHsmV2 MSBuild target should place both side-by-side; " +
                "auto-discovery of a system install is deliberately not supported.", builtUtil);
        return builtUtil;
    }

    internal static string GetRid()
    {
        // The native library must match the *process* architecture (the testhost), not the OS:
        // the win-x86 leg runs a 32-bit testhost under WOW64 on a 64-bit OS, so OSArchitecture would
        // wrongly resolve win-x64 and miss the win-x86 library the build placed.
        var arch = RuntimeInformation.ProcessArchitecture;
        if (OperatingSystem.IsLinux())
            return arch == Architecture.Arm64 ? "linux-arm64" : "linux-x64";
        if (OperatingSystem.IsMacOS())
            return arch == Architecture.Arm64 ? "osx-arm64" : "osx-x64";
        if (OperatingSystem.IsWindows())
            return arch switch
            {
                Architecture.Arm64 => "win-arm64",
                Architecture.X86 => "win-x86",
                _ => "win-x64",
            };
        return "linux-x64";
    }

    // -----------------------------------------------------------------------
    // libc setenv shim — Environment.SetEnvironmentVariable does not propagate
    // to native getenv() on Linux/macOS.
    // -----------------------------------------------------------------------

    [LibraryImport("libc", EntryPoint = "setenv", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LinuxSetEnv(string name, string value, int overwrite);

    [LibraryImport("libSystem.dylib", EntryPoint = "setenv", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int MacSetEnv(string name, string value, int overwrite);

    internal static void SetNativeEnv(string name, string value)
    {
        if (OperatingSystem.IsWindows()) return; // SetEnvironmentVariable already propagates here.
        int rc = OperatingSystem.IsMacOS() ? MacSetEnv(name, value, 1) : LinuxSetEnv(name, value, 1);
        if (rc != 0)
            throw new InvalidOperationException($"setenv({name}) failed with errno {Marshal.GetLastPInvokeError()}.");
    }

    // -----------------------------------------------------------------------
    // softhsm2-util runner
    // -----------------------------------------------------------------------

    private void RunUtil(string args, bool ignoreFailure = false)
    {
        // Point softhsm2-util at the libsofthsm2 we built and placed next to it. Without --module it
        // falls back to a module path compiled in at build time (a CMake/autotools install prefix);
        // that path doesn't exist in CI, so on Windows LoadLibrary fails with ERROR_MOD_NOT_FOUND
        // (0x7E). (Linux happens to work because the autotools install dir persists in the workspace.)
        var psi = new ProcessStartInfo(_utilPath, $"{args} --module \"{LibraryPath}\"")
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

/// <summary>
/// xUnit collection definition for the SoftHSM2 backend. Also hosts the spec-version-gate
/// fixtures (<see cref="SoftHsmGate240Fixture"/>, <see cref="SoftHsmGate30Fixture"/>):
/// they wrap private copies of the same libsofthsm2 and mutate process-global env vars
/// (SOFTHSM2_CONF, gate-target paths) during construction, so they must serialize with
/// every other SoftHSM-touching test.
/// </summary>
[CollectionDefinition("SoftHsm")]
public sealed class SoftHsmBackendCollection :
    ICollectionFixture<SoftHsmBackendFixture>,
    ICollectionFixture<SoftHsmGate240Fixture>,
    ICollectionFixture<SoftHsmGate30Fixture>
{ }
