using System.Reflection;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping FreeHSM — another fully independent real PKCS#11 implementation
/// alongside SoftHSM2, opencryptoki, NSS softoken, Kryoptic, BouncyHsm and Craton HSM. A C11 PKCS#11
/// v3.2 soft HSM on OpenSSL 3, with ML-KEM, ML-DSA and SLH-DSA, written to FIPS 140-3 discipline.
///
/// Uses the library built from the vendor/freehsm submodule and placed next to the test assembly by
/// the BuildFreeHsm MSBuild target; <see cref="Settings.FreeHsmLibraryPath"/> may override the path for
/// local debugging. Linux-only for now (see build-freehsm.sh).
///
/// Like Kryoptic, FreeHSM implements <c>C_InitToken</c>/<c>C_InitPIN</c> directly, so the token is
/// provisioned through the library under test. Everything the module writes (the token file, the
/// audit log and its key) goes to a fresh temporary directory named by <c>FHSM_TOKENS_DIR</c>, so every
/// run starts from a factory-state token and leaves nothing behind. Its configuration file
/// (<c>FHSM_CONF</c>) selects the permissive mode, in which the non-approved mechanisms the build
/// dispatches (RSA PKCS#1 v1.5, SHA-1, ...) run instead of being refused. The shared fixture PINs meet
/// its PIN rule (4 to 64 bytes); five wrong PINs in a row lock the PIN, so nothing here logs in with one.
/// </summary>
public sealed class FreeHsmBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when FreeHSM is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <inheritdoc/>
    // Multi-part AES-GCM encryption works, but C_DecryptUpdate/C_DecryptFinal never hand the tag (the last
    // ulTagBits/8 bytes of the ciphertext) to the cipher, so C_DecryptFinal refuses every ciphertext with
    // CKR_ENCRYPTED_DATA_INVALID. Single-part AES-GCM is unaffected.
    public bool SupportsMultipartAesGcm => false;

    private const int SlotNumber = 0;

    private readonly string _stateDir = string.Empty;

    public static bool FreeHsmAvailable =>
        (Settings.FreeHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    public FreeHsmBackendFixture()
    {
        string? libPath = Settings.FreeHsmLibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        // Owner-only by construction (CreateTempSubdirectory makes it 0700), which the module wants for
        // the directory holding its tokens and its audit-log key.
        _stateDir = Directory.CreateTempSubdirectory("kl-freehsm-").FullName;
        string configPath = Path.Join(_stateDir, "freehsm.conf");
        File.WriteAllText(configPath, "mode = permissive\n");

        // libfreehsm.so reads these through getenv() at C_Initialize time; as for Kryoptic, .NET's
        // Environment.SetEnvironmentVariable does not reach native getenv() on Linux, so setenv() too.
        SetEnv("FHSM_CONF", configPath);
        SetEnv("FHSM_TOKENS_DIR", _stateDir);

        // A signed module (build-freehsm.sh signs it) loads the OpenSSL FIPS provider at C_Initialize
        // and fails without one; the test OpenSSL has none. FHSM_INTEGRITY_ALLOW_UNSIGNED is upstream's
        // development switch for running test harnesses against such a build: the module runs on the
        // default provider instead. The boot integrity self-test and the known-answer tests still run.
        SetEnv("FHSM_INTEGRITY_ALLOW_UNSIGNED", "1");

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            // tokenPresent: false. FreeHSM leaves a slot whose token was never initialized out of the
            // tokenPresent list, although C_GetSlotInfo reports CKF_TOKEN_PRESENT for it.
            Pkcs11Slot slot = Library.GetSlotList(tokenPresent: false).FirstOrDefault(s => s.SlotId.Value == SlotNumber)
                ?? throw new InvalidOperationException($"FreeHSM slot {SlotNumber} did not appear in the slot list.");

            slot.InitTokenWithPin(new SecurePin(SoPin.Span), TokenLabel);

            using (Pkcs11Session so = Library.OpenSessionWithPin(TokenLabel, CKU.CKU_SO, new SecurePin(SoPin.Span)))
            {
                so.InitPinWithPin(new SecurePin(UserPin.Span));
            }

            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch (Exception e) when (e is Pkcs11Exception or InvalidOperationException)
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
            if (_stateDir.Length > 0)
                Directory.Delete(_stateDir, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: a leftover directory under the temp path holds only throwaway test state.
        }
    }

    private static void SetEnv(string name, string value)
    {
        Environment.SetEnvironmentVariable(name, value);
        KryopticBackendFixture.SetNativeEnv(name, value);
    }

    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(asmDir, "runtimes", KryopticBackendFixture.GetRid(), "native", "libfreehsm.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the FreeHSM backend.</summary>
[CollectionDefinition("FreeHsm")]
public sealed class FreeHsmBackendCollection : ICollectionFixture<FreeHsmBackendFixture>
{ }
