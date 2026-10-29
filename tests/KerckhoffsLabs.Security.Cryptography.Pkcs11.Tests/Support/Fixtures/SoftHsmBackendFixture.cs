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

    // SupportsMlDsa/MlKem/SlhDsa use the default interface member (advertised mechanism list):
    // WITH_ML_DSA/WITH_ML_KEM gate the mechanism's entry into SoftHSM's own supportedMechanisms
    // set (vendor/softhsmv2/src/lib/SoftHSM.cpp), which is the same C_GetMechanismList this
    // fixture already reads into SupportedMechanisms — no separate build marker needed.

    /// <inheritdoc/>
    // SoftHSM 2.7 returns CKR_ENCRYPTED_DATA_INVALID for an AEAD tag-verification failure; pin it so
    // the authenticity tests assert the exact code. SoftHSM 2.5 (the v2.40 leg) instead returns
    // CKR_GENERAL_ERROR, which the AEAD adapters deliberately do not map, so there the tests prove the
    // forgery is still rejected, as a Pkcs11Exception carrying that code.
    public CKR? AeadAuthFailureCode(CKM mechanism) =>
        IsV240Leg ? CKR.CKR_GENERAL_ERROR : CKR.CKR_ENCRYPTED_DATA_INVALID;

    /// <inheritdoc/>
    // SoftHSM decodes an Edwards CKA_EC_POINT with DERUTIL::octet2Raw (OSSLEDPublicKey::createOSSLKey),
    // so a raw point is stored but every use of the key fails; it also writes the DER form on keygen.
    // Asked upstream to accept the raw form too: https://github.com/softhsm/SoftHSMv2/issues/909.
    public bool EcxPointIsDerEncoded => true;

    /// <summary>True on the dedicated SoftHSM 2.5 leg (see <c>SoftHsmV240ComplianceTests</c>), which
    /// loads a v2.40-only module whose exact error codes differ from the modern build's.</summary>
    internal static bool IsV240Leg =>
        string.Equals(Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_SOFTHSM_V240"), "1", StringComparison.Ordinal);

    // === SoftHSM 2.7 capability gates ======================================
    // These are static so they can be passed to [Fact(SkipUnless = nameof(...))],
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

    // Parent directory that SoftHSM2 creates UUID token subdirs inside.
    private readonly string _tokenStoreDir;
    private readonly string _configPath;
    private readonly string _utilPath;

    public static bool SoftHsmAvailable =>
        (Settings.SoftHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    /// <summary>
    /// False while <c>C_GenerateKey</c> and <c>C_GenerateKeyPair</c> answer a template whose <c>CKA_CLASS</c> the
    /// mechanism does not make (<c>CKO_DATA</c> from <c>CKM_AES_KEY_GEN</c>, <c>CKO_PRIVATE_KEY</c> in the public
    /// template of <c>CKM_EC_KEY_PAIR_GEN</c>) with <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, where PKCS#11 v3.2 §5.18.1
    /// and §5.18.2 answer <c>CKR_TEMPLATE_INCONSISTENT</c>. Nothing is created.
    /// </summary>
    public const bool SoftHsmReportsAContradictoryClassAsInconsistent = false;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_AES_KEY_WRAP)</c> of a blob that fails RFC 3394's integrity check answers
    /// <c>CKR_GENERAL_ERROR</c>: <c>UnwrapKeySym</c> in <c>src/lib/SoftHSM.cpp</c> reports any failed decryption so.
    /// PKCS#11 v3.2 §5.1.6 and §5.18.4: <c>CKR_WRAPPED_KEY_INVALID</c>. A blob of the wrong length is refused with
    /// <c>CKR_WRAPPED_KEY_LEN_RANGE</c>, as it should be.
    /// </summary>
    public const bool SoftHsmReportsATamperedKeyWrapBlobAsInvalid = false;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_RSA_PKCS_OAEP)</c> of a blob that is not the modulus's length answers
    /// <c>CKR_GENERAL_ERROR</c>: <c>UnwrapKeyAsym</c> in <c>src/lib/SoftHSM.cpp</c> does not check the length and
    /// reports the failed decryption so. PKCS#11 v3.2 §5.1.6 and §5.18.4: <c>CKR_WRAPPED_KEY_LEN_RANGE</c>.
    /// </summary>
    public const bool SoftHsmRefusesAnOaepBlobByItsLength = false;

    /// <summary>Gate for the RSA-OAEP wrapped-key length case: see <see cref="SoftHsmRefusesAnOaepBlobByItsLength"/>.</summary>
    public static bool OaepBlobLengthRefusalAvailable => SoftHsmAvailable && SoftHsmRefusesAnOaepBlobByItsLength;

    /// <summary>
    /// False while <c>C_Verify(CKM_RSA_X_509)</c> with more data than the modulus has bytes ends the test process:
    /// <c>AsymVerify</c> in <c>src/lib/SoftHSM.cpp</c> zero-pads the data to the modulus's length with
    /// <c>data.wipe(size - ulDataLen)</c>, which wraps around for <c>ulDataLen &gt; size</c>. PKCS#11 v3.2 §6.1.12
    /// (Table 45: at most k bytes) and §5.1.6: <c>CKR_DATA_LEN_RANGE</c>. Not yet reported upstream.
    /// </summary>
    public const bool SoftHsmSurvivesAnOverlongRawRsaVerify = false;

    /// <summary>Gate for the over-long raw RSA verify case: see <see cref="SoftHsmSurvivesAnOverlongRawRsaVerify"/>.</summary>
    public static bool OverlongRawRsaVerifyAvailable => SoftHsmAvailable && SoftHsmSurvivesAnOverlongRawRsaVerify;

    /// <summary>
    /// False while <c>C_DigestKey</c> digests the <c>CKA_VALUE</c> of any object that has one, a sensitive EC private
    /// key's scalar included: <c>C_DigestKey</c> in <c>src/lib/SoftHSM.cpp</c> checks neither the class nor, for
    /// SHA-1 and SHA-2, <c>CKA_SENSITIVE</c> or <c>CKA_EXTRACTABLE</c>. Confirmed with an imported P-256 key: the
    /// digest is SHA-256 of its private scalar. PKCS#11 v3.2 §5.12.4 digests "the value of a secret key", and
    /// §5.1.6 has a key that is not one answer <c>CKR_KEY_INDIGESTIBLE</c>. Not yet reported upstream.
    /// </summary>
    public const bool SoftHsmRefusesToDigestAPrivateKey = false;

    /// <summary>Gate for the private-key <c>C_DigestKey</c> case: see <see cref="SoftHsmRefusesToDigestAPrivateKey"/>.</summary>
    public static bool PrivateKeyDigestRefusalAvailable => SoftHsmAvailable && SoftHsmRefusesToDigestAPrivateKey;

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

        // Write config next to the library so the baked-in DEFAULT_SOFTHSM2_CONF is satisfied.
        string nativeDir = Path.GetDirectoryName(libPath)!;
        _configPath = Path.Join(nativeDir, "softhsm2.conf");

        // On Windows, every token-object path SoftHSM2 creates here
        // (<nativeDir>\tokens\<token-uuid>\<object-uuid>.object) lands at 278 characters --
        // 18 over the classic Win32 MAX_PATH (260) -- because of how deep GitHub Actions'
        // checkout ("D:\a\<repo>\<repo>\...") plus this project's own build output path nest.
        // The vendored SoftHSM2 Windows build opens object files via narrow, non-long-path-aware
        // fopen()/CreateFileA, so every C_CreateObject/C_GenerateKey* for a CKA_TOKEN object
        // fails with ERROR_PATH_NOT_FOUND ("No such file or directory" -> CKR_GENERAL_ERROR),
        // confirmed via SoftHSM's own DEBUG log: 100% of "Created new object" attempts were
        // immediately followed by that exact failure, with zero exceptions. Session objects
        // (no on-disk file) are unaffected, which is why some tests still passed. Rooting the
        // token store at a short, OS-temp-based path instead keeps every object path comfortably
        // under 260 chars regardless of how deep the repo checkout is.
        _tokenStoreDir = OperatingSystem.IsWindows()
            ? Path.Join(Path.GetTempPath(), "sthsm-" + Guid.NewGuid().ToString("N")[..8])
            : Path.Join(nativeDir, "tokens");

        // Start from an empty store. Dispose deletes it, but a run killed mid-way (a test timeout, Ctrl+C)
        // leaves what it had: a token whose directory was created but never initialized cannot be read
        // by softhsm2-util, so neither --delete-token nor --init-token gets past it, and every later run
        // fails here.
        if (Directory.Exists(_tokenStoreDir))
            Directory.Delete(_tokenStoreDir, recursive: true);
        Directory.CreateDirectory(_tokenStoreDir);

        File.WriteAllText(_configPath,
            $"directories.tokendir = {_tokenStoreDir}\n" +
            "objectstore.backend = file\n" +
            "log.level = ERROR\n");

        RunUtil("--init-token --free " +
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

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            var slots = Library.GetSlotList();
            Pkcs11Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"SoftHSM2 token '{TokenLabel}' did not appear in slot list.");
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
        string candidate = Path.Join(asmDir, "runtimes", GetRid(), "native", $"libsofthsm2.{ext}");
        return File.Exists(candidate) ? candidate : null;
    }

    internal static string ResolveUtil(string libPath)
    {
        string utilName = OperatingSystem.IsWindows() ? "softhsm2-util.exe" : "softhsm2-util";
        string builtUtil = Path.Join(Path.GetDirectoryName(libPath), utilName);
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

    [LibraryImport("libc", EntryPoint = "unsetenv", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LinuxUnsetEnv(string name);

    [LibraryImport("libSystem.dylib", EntryPoint = "unsetenv", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int MacUnsetEnv(string name);

    /// <summary>Sets <paramref name="name"/> for native code, or removes it when <paramref name="value"/> is null.</summary>
    internal static void SetOrUnsetNativeEnv(string name, string? value)
    {
        if (value is not null)
        {
            SetNativeEnv(name, value);
            return;
        }
        if (OperatingSystem.IsWindows()) return;
        int rc = OperatingSystem.IsMacOS() ? MacUnsetEnv(name) : LinuxUnsetEnv(name);
        if (rc != 0)
            throw new InvalidOperationException($"unsetenv({name}) failed with errno {Marshal.GetLastPInvokeError()}.");
    }

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
        // (0x7E). (Linux happens to work because the autotools install dir persists in the session.)
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
