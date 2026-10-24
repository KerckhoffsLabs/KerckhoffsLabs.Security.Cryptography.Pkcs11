using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping Craton HSM (craton-hsm-core) — another fully independent real
/// PKCS#11 implementation alongside SoftHSM2, opencryptoki, NSS softoken, Kryoptic and BouncyHsm. Pure Rust on the
/// RustCrypto crates (no OpenSSL), PKCS#11 v3.0, with ML-KEM, ML-DSA and SLH-DSA: a second real backend
/// for the post-quantum families that does not share Kryoptic's or SoftHSM's OpenSSL code.
///
/// Uses the library built from the vendor/craton-hsm-core submodule and placed next to the test
/// assembly by the BuildCratonHsm MSBuild target; <see cref="Settings.CratonHsmLibraryPath"/> may
/// override the path for local debugging. Linux-only for now (see build-craton-hsm.sh).
///
/// Like Kryoptic, Craton HSM implements <c>C_InitToken</c>/<c>C_InitPIN</c> directly, so the token is
/// provisioned through the library under test. Its configuration is a TOML file named by
/// <c>CRATON_HSM_CONFIG</c>, written next to the library with owner-only permissions (the module
/// refuses a group-writable one): objects are kept in memory only
/// (<c>persist_objects = false</c>), so every run starts from a factory-state token and leaves no store
/// behind; the audit log is off, so no log file lands in the working directory; and PBKDF2 runs at the
/// minimum the module accepts (100,000 iterations, SP 800-132) rather than its 600,000 default, since
/// the fixture PINs protect nothing.
/// </summary>
public sealed class CratonHsmBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    // Craton HSM rejects a PIN with fewer than 3 distinct bytes or 2 character classes
    // (CKR_PIN_INVALID), so the shared 11111111 default can't be used; like opencryptoki, this
    // backend has PINs of its own.
    public ReadOnlyMemory<byte> SoPin { get; } = "craton-so-1234"u8.ToArray();
    public ReadOnlyMemory<byte> UserPin { get; } = "craton-user-1234"u8.ToArray();
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when Craton HSM is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <inheritdoc/>
    // "AES-GCM and RSA-OAEP are single-shot only" (src/pkcs11_abi/functions.rs): C_EncryptUpdate
    // answers CKR_MECHANISM_INVALID.
    public bool SupportsMultipartAesGcm => false;

    /// <inheritdoc/>
    // Signing is deterministic with an empty context, and resolve_pqc_sign_mechanism
    // (src/pkcs11_abi/functions.rs) refuses a non-empty one rather than ignore it.
    public bool SupportsPqcSignContext => false;

    /// <inheritdoc/>
    // Only SHA2-128s and SHA2-256s (CKP 1 and 9); its CKM_SLH_DSA_KEY_PAIR_GEN key-size range of 1..9
    // names those two, not the seven in between.
    public CkpSlhDsa SlhDsaTestParameterSet => CkpSlhDsa.CKP_SLH_DSA_SHA2_128S;

    private const int SlotNumber = 0;

    private readonly string _configPath = string.Empty;

    public static bool CratonHsmAvailable =>
        (Settings.CratonHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    public CratonHsmBackendFixture()
    {
        string? libPath = Settings.CratonHsmLibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        _configPath = Path.Join(Path.GetDirectoryName(libPath)!, "craton_hsm.toml");
        File.WriteAllText(_configPath,
            "[token]\n" +
            "persist_objects = false\n" +
            "slot_count = 1\n" +
            "\n" +
            "[security]\n" +
            "pbkdf2_iterations = 100000\n" +
            "\n" +
            "[audit]\n" +
            "enabled = false\n");

        // C_Initialize refuses a config file that is group- or world-writable, and the default umask
        // leaves it 664. Owner-only is what the module asks for. (Linux only, like the whole fixture.)
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_configPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        // libcraton_hsm.so reads CRATON_HSM_CONFIG at C_Initialize time; as for Kryoptic, .NET's
        // Environment.SetEnvironmentVariable does not reach native getenv() on Linux, so setenv() too.
        Environment.SetEnvironmentVariable("CRATON_HSM_CONFIG", _configPath);
        KryopticBackendFixture.SetNativeEnv("CRATON_HSM_CONFIG", _configPath);

        // The power-on self-test verifies the library's signature against a key embedded at build time
        // (CRATON_HSM_INTEGRITY_PUBLIC_KEY); a build from source has only the all-zeros placeholder, so
        // C_Initialize fails with CKR_GENERAL_ERROR. Upstream's switch for local and test use skips that
        // one check; the algorithm known-answer tests still run.
        Environment.SetEnvironmentVariable("CRATON_HSM_INTEGRITY_BYPASS", "unsafe-dev-only");
        KryopticBackendFixture.SetNativeEnv("CRATON_HSM_INTEGRITY_BYPASS", "unsafe-dev-only");

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.SlotId.Value == SlotNumber)
                ?? throw new InvalidOperationException($"Craton HSM slot {SlotNumber} did not appear in the slot list.");

            slot.InitTokenWithPin(new SecurePin(SoPin.Span), TokenLabel);

            using (Pkcs11Session so = Library.OpenSessionWithPin(TokenLabel, CKU.CKU_SO, new SecurePin(SoPin.Span)))
            {
                so.InitPinWithPin(new SecurePin(UserPin.Span));
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
        Library?.Dispose();
        try
        {
            if (_configPath.Length > 0)
                File.Delete(_configPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: a config left next to the library is rewritten by the next run.
        }
    }

    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(asmDir, "runtimes", KryopticBackendFixture.GetRid(), "native", "libcraton_hsm.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the Craton HSM backend.</summary>
[CollectionDefinition("CratonHsm")]
public sealed class CratonHsmBackendCollection : ICollectionFixture<CratonHsmBackendFixture>
{ }
