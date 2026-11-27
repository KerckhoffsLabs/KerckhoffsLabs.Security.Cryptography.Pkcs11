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
///
/// <c>SignEdDsaContextTests</c> has no FreeHSM wrapper: the module signs pure Ed25519 / Ed448 only and refuses a
/// <c>CK_EDDSA_PARAMS</c> with a context or <c>phFlag</c> (<c>CKR_MECHANISM_PARAM_INVALID</c>) by design, rather than
/// sign something other than what was asked.
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

    private const int SlotNumber = 0;

    // FreeHSM offers four slots; the second is TokenAdministrationTestCases' to initialize at will.
    private const int ScratchSlotNumber = 1;

    /// <inheritdoc/>
    public NativeCULong? ScratchSlotId { get; }

    private readonly string _stateDir = string.Empty;

    public static bool FreeHsmAvailable =>
        (Settings.FreeHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    /// <summary>
    /// False while <c>C_CreateObject</c> refuses a DSA key with <c>CKR_TEMPLATE_INCONSISTENT</c>. 2.8.0 generates DSA key
    /// pairs and signs and verifies with them, but has no import path for <c>CKK_DSA</c>, public or private, so a
    /// Wycheproof public key or a certificate's private key cannot be put on the token. afchine1337/freehsm#42.
    /// </summary>
    public const bool FreeHsmImportsDsaKeys = false;

    /// <summary>Gate for the cases that import a DSA key: see <see cref="FreeHsmImportsDsaKeys"/>.</summary>
    public static bool DsaImportAvailable => FreeHsmAvailable && FreeHsmImportsDsaKeys;

    /// <summary>
    /// False while <c>CKM_IKE1_PRF_DERIVE</c> refuses an <c>hKeygxy</c> without <c>CKA_DERIVE</c> with
    /// <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c> (<c>ike_aux_key</c> in <c>src/fhsm_pkcs11.c</c> checks the derive usage, as
    /// for HKDF's salt key). PKCS#11 v3.2 §6.64.4 asks only that <c>hKeygxy</c> be a <c>CKK_GENERIC_SECRET</c>: its value
    /// is data for the prf, not a base key. NSS and Kryoptic take it without <c>CKA_DERIVE</c>.
    /// afchine1337/freehsm#43.
    /// </summary>
    public const bool FreeHsmTakesAnIkeGxyKeyWithoutDerive = false;

    /// <summary>Gate for the <c>CKM_IKE1_PRF_DERIVE</c> cases: see <see cref="FreeHsmTakesAnIkeGxyKeyWithoutDerive"/>.</summary>
    public static bool Ike1PrfAvailable => FreeHsmAvailable && FreeHsmTakesAnIkeGxyKeyWithoutDerive;

    /// <summary>
    /// False while the IKE derivations take a <c>CKK_GENERIC_SECRET</c> base key with <c>bDataAsKey</c> FALSE
    /// (<c>ike_prf_key_type_ok</c> admits it beside the HMAC key types). PKCS#11 v3.2 §6.64.3: the base key "must be of
    /// type CKK_GENERIC_SECRET if bDataAsKey is TRUE and the key type of the underlying prf if bDataAsKey is FALSE";
    /// Kryoptic answers <c>CKR_KEY_TYPE_INCONSISTENT</c>. afchine1337/freehsm#43.
    /// </summary>
    public const bool FreeHsmRefusesAGenericSecretIkeBaseKey = false;

    /// <summary>Gate for the IKE base-key-type case: see <see cref="FreeHsmRefusesAGenericSecretIkeBaseKey"/>.</summary>
    public static bool IkeBaseKeyTypeCheckAvailable => FreeHsmAvailable && FreeHsmRefusesAGenericSecretIkeBaseKey;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_CONCATENATE_BASE_AND_KEY)</c> ignores the second key's <c>CKA_ALLOWED_MECHANISMS</c>:
    /// a second key whose list leaves the mechanism out is concatenated anyway, and only the base key's list is
    /// checked. PKCS#11 v3.2 §4.8 Table 26: the list names the mechanisms "allowed to be used with this key",
    /// which we read as covering both keys of the derivation (BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced).
    /// </summary>
    public const bool FreeHsmChecksTheSecondKeysAllowedMechanisms = false;

    /// <summary>
    /// False while <c>C_SetPIN</c> checks the old PIN and stores the new one under two separate holds of the token's
    /// lock: <c>fhsm_token_set_pin</c> in <c>src/fhsm_token.c</c> verifies the old PIN (<c>token_verify_pin_dek</c>)
    /// before it takes <c>t-&gt;mu</c> to store the new one. Four sessions changing the user PIN from the same old PIN at
    /// once see two, three or all four calls answer <c>CKR_OK</c> (3 runs in 4 at v2.8.0), and the PIN left is the last
    /// one stored. PKCS#11 v3.2 §5.4: a module initialized with <c>CKF_OS_LOCKING_OK</c> may be called from several
    /// threads, so the outcome must be one the calls could have had in some order, where only the first finds the old
    /// PIN. The library sends one PIN to a slot at a time, so its own <c>SetPinWithPin</c> is not affected. Not yet
    /// reported upstream. No tripwire: the race is not lost every time.
    /// </summary>
    public const bool FreeHsmSetsAPinAtomically = false;

    /// <summary>Gate for the raw concurrent <c>C_SetPIN</c> case: see <see cref="FreeHsmSetsAPinAtomically"/>.</summary>
    public static bool AtomicSetPinAvailable => FreeHsmAvailable && FreeHsmSetsAPinAtomically;

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

            // The SO sets the user PIN (C_InitPIN on its login's own read/write session); disposing the login logs out.
            using (var soPin = new SecurePin(SoPin.Span))
            using (Pkcs11Login so = slot.Login(TokenUser.SecurityOfficer, soPin))
            using (var userPin = new SecurePin(UserPin.Span))
            {
                so.InitUserPinWithPin(userPin);
            }

            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
            if (Library.GetSlotList(tokenPresent: false).Any(s => s.SlotId.Value == ScratchSlotNumber))
                ScratchSlotId = (NativeCULong)ScratchSlotNumber;
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
