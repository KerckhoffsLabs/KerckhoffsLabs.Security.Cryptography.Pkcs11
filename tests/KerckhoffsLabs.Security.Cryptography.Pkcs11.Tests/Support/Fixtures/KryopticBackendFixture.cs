using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping Kryoptic — a fourth, fully independent real PKCS#11
/// implementation (Rust, OpenSSL-backed) alongside SoftHSM2, opencryptoki, and NSS softoken.
/// NSS already covers ChaCha20-Poly1305 and the SP800-108 counter KDF on a real token, but
/// AES-CCM and SLH-DSA still had zero real-backend coverage — Kryoptic implements both (confirmed
/// via its own <c>C_GetMechanismList</c>: <see cref="CKM.CKM_AES_CCM"/> and <see cref="CKM.CKM_SLH_DSA"/>
/// are both advertised), closing the remaining gap instead of leaving those two families'
/// <c>CK_*_PARAMS</c> marshalling verified only by the in-process <c>ManagedSoftToken</c> fake.
/// Kryoptic also now implements <c>CKM_CHACHA20_POLY1305</c>, giving that family a second real
/// backend alongside NSS.
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

    // SupportsMlDsa/MlKem/SlhDsa intentionally use IPkcs11Backend's default implementations (the
    // advertised C_GetMechanismList): no SoftHSM-style build-marker override is needed because this
    // backend is built with `pqc` on every leg that runs it (see build-kryoptic.sh) — the mechanism
    // list already tells the truth.

    /// <inheritdoc/>
    // Kryoptic reports a failed AES-CCM tag check through C_DecryptMessage as CKR_DEVICE_ERROR, a code
    // the AEAD adapters deliberately do not map; pin it so the tests prove it stays a Pkcs11Exception.
    // AES-GCM and ChaCha20-Poly1305 report a mapped code, which is left unpinned.
    public CKR? AeadAuthFailureCode(CKM mechanism) =>
        mechanism == CKM.CKM_AES_CCM ? CKR.CKR_DEVICE_ERROR : null;

    /// <summary>True if the token supports <see cref="CKM.CKM_CHACHA20_POLY1305"/>. Added upstream
    /// alongside <c>CKM_CHACHA20</c> — before that, Kryoptic had no ChaCha20 support of any kind and
    /// NSS softoken was the only real backend for this mechanism family.</summary>
    public static bool KryopticSupportsChaCha20Poly1305 => true;

    private const int SlotNumber = 0;

    private readonly string _configPath = string.Empty;
    private readonly string _dbPath = string.Empty;

    public static bool KryopticAvailable =>
        (Settings.KryopticLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    /// <summary>
    /// False while Kryoptic checks the login only for token objects (<c>create_object</c> and
    /// <c>insert_object</c> in <c>src/token.rs</c>): with nobody logged in, <c>C_CreateObject</c>,
    /// <c>C_CopyObject</c>, <c>C_GenerateKey</c>, <c>C_GenerateKeyPair</c>, <c>C_DeriveKey</c>, <c>C_UnwrapKey</c>,
    /// <c>C_EncapsulateKey</c> and <c>C_DecapsulateKey</c> all make a <c>CKA_PRIVATE = TRUE</c> session object; and
    /// any login counts, so the SO makes one too. PKCS#11 v3.2 §5.1.6 (<c>CKR_USER_NOT_LOGGED_IN</c>) and §5.7.1:
    /// only public objects can be created unless the normal user is logged in.
    /// </summary>
    public const bool KryopticRefusesPrivateObjectsWithoutALogin = false;

    /// <summary>Gate for the private-object cases (nobody, or the SO, logged in): see <see cref="KryopticRefusesPrivateObjectsWithoutALogin"/>.</summary>
    public static bool PrivateObjectLoginCheckAvailable => KryopticAvailable && KryopticRefusesPrivateObjectsWithoutALogin;

    /// <summary>
    /// False while <c>C_EncryptInit</c> with the handle of a private token key after <c>C_Logout</c> answers
    /// <c>CKR_GENERAL_ERROR</c>, a code that says the token failed rather than that the key may not be used.
    /// PKCS#11 v3.2 §5.6.10 makes every handle to a private object invalid on <c>C_Logout</c>; §5.8.1 refuses it
    /// with <c>CKR_KEY_HANDLE_INVALID</c> or <c>CKR_USER_NOT_LOGGED_IN</c>.
    /// </summary>
    public const bool KryopticRefusesAPrivateKeyAfterLogout = false;

    /// <summary>
    /// False while a read-only session copies and refuses to destroy token objects off the spec: <c>C_CopyObject</c>
    /// of a token object whose template does not name <c>CKA_TOKEN</c> makes a token object (<c>copy_object</c> in
    /// <c>src/fns/objmgmt.rs</c> checks only the template), and <c>C_DestroyObject</c> of a token object answers
    /// <c>CKR_ACTION_PROHIBITED</c>, which says the object is not destroyable. PKCS#11 v3.2 §5.7.2 and §5.7.3: only
    /// session objects can be created or destroyed in a read-only session (<c>CKR_SESSION_READ_ONLY</c>).
    /// </summary>
    public const bool KryopticRefusesTokenObjectWritesInReadOnlySessions = false;

    /// <summary>
    /// False while <c>C_SetPIN</c> takes a PIN shorter than the token's own <c>ulMinPinLen</c>: <c>C_GetTokenInfo</c>
    /// reports 8 (<c>src/token.rs</c>), but only the NSS database storage checks a PIN's length, so a 7-byte PIN is
    /// set. PKCS#11 v3.2 §5.5.9 and §5.1.6: a PIN of a length outside the range is <c>CKR_PIN_LEN_RANGE</c>.
    /// </summary>
    public const bool KryopticEnforcesItsMinimumPinLength = false;

    /// <summary>Gate for the PIN length case: see <see cref="KryopticEnforcesItsMinimumPinLength"/>.</summary>
    public static bool PinLengthRangeAvailable => KryopticAvailable && KryopticEnforcesItsMinimumPinLength;

    /// <summary>
    /// False while a <c>CKA_UNIQUE_ID</c> from the caller is refused with other codes than
    /// <c>CKR_ATTRIBUTE_READ_ONLY</c>: <c>C_CreateObject</c> with one answers <c>CKR_ATTRIBUTE_TYPE_INVALID</c> and
    /// <c>C_SetAttributeValue</c> of one <c>CKR_ACTION_PROHIBITED</c>, and <c>C_GenerateKeyPair</c> with one in the
    /// private key's template makes the key pair; <c>C_CopyObject</c> answers <c>CKR_ATTRIBUTE_READ_ONLY</c>.
    /// PKCS#11 v3.2 §4.4.1: such operations "MUST fail" with <c>CKR_ATTRIBUTE_READ_ONLY</c>.
    /// </summary>
    public const bool KryopticRefusesAUniqueIdWithReadOnly = false;

    /// <summary>
    /// False while a secret key's <c>CKA_VALUE</c> can be changed: <c>C_SetAttributeValue</c> of a new
    /// <c>CKA_VALUE</c> on a non-sensitive AES key, and <c>C_CopyObject</c> with one in the template, answer
    /// <c>CKR_OK</c> and the key takes the new value. PKCS#11 v3.2 §6.7 (no footnote 8 on <c>CKA_VALUE</c>),
    /// §4.1.2 and §4.1.3: <c>CKR_ATTRIBUTE_READ_ONLY</c>. RSA and EC public key material is refused.
    /// </summary>
    public const bool KryopticFixesASecretKeysValue = false;

    /// <summary>
    /// False while <c>CKA_ALWAYS_SENSITIVE</c> and <c>CKA_NEVER_EXTRACTABLE</c> in a template are not refused with
    /// <c>CKR_ATTRIBUTE_READ_ONLY</c>: <c>C_GenerateKey</c> takes either (with the opposite of what it would
    /// record) and <c>C_CreateObject</c> answers <c>CKR_ATTRIBUTE_TYPE_INVALID</c>. PKCS#11 v3.2 §4.11 footnotes
    /// 2 and 4 (MUST NOT be specified) and §4.1.1 point 3.
    /// </summary>
    public const bool KryopticRefusesProvenanceAttributesInATemplate = false;

    /// <summary>Gate for the CKA_UNIQUE_ID case: see <see cref="KryopticRefusesAUniqueIdWithReadOnly"/>.</summary>
    public static bool UniqueIdRefusalAvailable => KryopticAvailable && KryopticRefusesAUniqueIdWithReadOnly;

    /// <summary>Gate for the provenance-in-a-template case: see <see cref="KryopticRefusesProvenanceAttributesInATemplate"/>.</summary>
    public static bool ProvenanceTemplateRefusalAvailable => KryopticAvailable && KryopticRefusesProvenanceAttributesInATemplate;

    /// <summary>
    /// False while an attribute with a NULL <c>pValue</c> and a non-zero <c>ulValueLen</c> is not refused:
    /// <c>C_CreateObject</c> with <c>CKA_TOKEN</c> given as <c>{NULL, 1}</c> crashes the process (SIGSEGV), and
    /// with <c>CKA_VALUE</c> given as <c>{NULL, 16}</c> makes a data object with an empty value and answers
    /// <c>CKR_OK</c>. PKCS#11 v3.2 §4.1.1 point 2 (<c>CKR_ATTRIBUTE_VALUE_INVALID</c>), or
    /// <c>CKR_ARGUMENTS_BAD</c>. No tripwire: reproducing the crash would take the test host down.
    /// </summary>
    public const bool KryopticRefusesANullAttributeValue = false;

    /// <summary>
    /// False while <c>CKM_ECDH1_DERIVE</c> gives the derived key <c>CKA_ALWAYS_SENSITIVE = TRUE</c> from a base
    /// key whose <c>CKA_ALWAYS_SENSITIVE</c> is FALSE (an EC private key imported sensitive with
    /// <c>C_CreateObject</c>). PKCS#11 v3.2 §6.3.17: "If the base key has its CKA_ALWAYS_SENSITIVE attribute set to
    /// CK_FALSE, then the derived key will as well." <c>CKM_HKDF_DERIVE</c> follows the rule.
    /// </summary>
    public const bool KryopticDerivesAnEcdhKeysHistoryFromTheBase = false;

    /// <summary>
    /// False while an HMAC key whose <c>CKA_SIGN</c> (<c>CKA_VERIFY</c>) is FALSE is refused by
    /// <c>C_SignInit</c> (<c>C_VerifyInit</c>) with <c>CKR_KEY_TYPE_INCONSISTENT</c>
    /// (<c>check_and_fetch_key</c> in <c>src/hmac.rs</c>), where PKCS#11 v3.2 §5.1.6 has
    /// <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c> for a key of the right type whose attributes do not allow the use.
    /// AES keys with <c>CKA_ENCRYPT</c> or <c>CKA_DECRYPT</c> FALSE, and derivation and ML-KEM keys, get
    /// <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.
    /// </summary>
    public const bool KryopticRefusesAnUnpermittedMacKeyAsNotPermitted = false;

    /// <summary>Gate for the HMAC key-usage cases: see <see cref="KryopticRefusesAnUnpermittedMacKeyAsNotPermitted"/>.</summary>
    public static bool MacKeyUsageRefusalAvailable => KryopticAvailable && KryopticRefusesAnUnpermittedMacKeyAsNotPermitted;

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
        _configPath = Path.Join(nativeDir, "kryoptic.conf");
        _dbPath = Path.Join(nativeDir, "kryoptic-token.sql");
        try { File.Delete(_dbPath); } catch { /* best-effort */ }

        File.WriteAllText(_configPath,
            "[[slots]]\n" +
            $"slot = {SlotNumber}\n" +
            "dbtype = \"sqlite\"\n" +
            $"dbargs = \"{_dbPath.Replace("\\", "\\\\")}\"\n");

        // libkryoptic_pkcs11.so reads KRYOPTIC_CONF via getenv() at C_Initialize time, same
        // caveat as SoftHSM2_CONF: .NET's Environment.SetEnvironmentVariable does not propagate
        // to native getenv() on Linux, so call setenv() directly too.
        Environment.SetEnvironmentVariable("KRYOPTIC_CONF", _configPath);
        SetNativeEnv("KRYOPTIC_CONF", _configPath);

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.SlotId.Value == SlotNumber)
                ?? throw new InvalidOperationException($"Kryoptic slot {SlotNumber} did not appear in the slot list.");

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
        try { Library?.Dispose(); } catch { /* best-effort */ }
        try { if (_configPath.Length > 0) File.Delete(_configPath); } catch { /* best-effort */ }
        try { if (_dbPath.Length > 0) File.Delete(_dbPath); } catch { /* best-effort */ }
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
