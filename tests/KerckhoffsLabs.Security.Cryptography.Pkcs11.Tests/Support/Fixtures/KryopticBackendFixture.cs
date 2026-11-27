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
    // Since v1.5.5 (latchset/kryoptic d01ea71) Kryoptic reports a failed AES-CCM or AES-GCM tag check as
    // CKR_AEAD_DECRYPT_FAILED; AES-CCM answered CKR_DEVICE_ERROR before. ChaCha20-Poly1305 reports another
    // tag-failure code, which is left unpinned.
    public CKR? AeadAuthFailureCode(CKM mechanism) =>
        mechanism is CKM.CKM_AES_CCM or CKM.CKM_AES_GCM ? CKR.CKR_AEAD_DECRYPT_FAILED : null;

    /// <summary>True if the token supports <see cref="CKM.CKM_CHACHA20_POLY1305"/>. Added upstream
    /// alongside <c>CKM_CHACHA20</c> — before that, Kryoptic had no ChaCha20 support of any kind and
    /// NSS softoken was the only real backend for this mechanism family.</summary>
    public static bool KryopticSupportsChaCha20Poly1305 => true;

    private const int SlotNumber = 0;

    // A second slot, with a token store of its own, which TokenAdministrationTestCases initialize at will.
    private const int ScratchSlotNumber = 1;

    private readonly string _configPath = string.Empty;
    private readonly string _dbPath = string.Empty;
    private readonly string _scratchDbPath = string.Empty;

    /// <inheritdoc/>
    public NativeCULong? ScratchSlotId => _scratchDbPath.Length > 0 ? (NativeCULong)ScratchSlotNumber : null;

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

    /// <summary>
    /// False while a data object or certificate given as the wrapping key of <c>C_WrapKey</c> or the unwrapping
    /// key of <c>C_UnwrapKey</c> is refused with <c>CKR_GENERAL_ERROR</c>: <c>wrap_key</c> and <c>unwrap_key</c> in
    /// <c>src/fns/keymgmt.rs</c> read its <c>CKA_WRAP</c> (<c>CKA_UNWRAP</c>), which the object does not have, and
    /// pass the lookup's error on. PKCS#11 v3.2 §5.18.3 and §5.18.4: <c>CKR_WRAPPING_KEY_HANDLE_INVALID</c>
    /// (<c>CKR_UNWRAPPING_KEY_HANDLE_INVALID</c>) or a key-type or key-function code.
    /// </summary>
    public const bool KryopticRefusesANonKeyObjectAsAWrappingKey = false;

    /// <summary>
    /// False while <c>CKM_HKDF_DERIVE</c> from an EC private key answers <c>CKR_KEY_HANDLE_INVALID</c>
    /// (<c>src/ossl/hkdf.rs</c> refuses every class but a secret key or a data object that way). The handle names
    /// a valid key of the wrong type: PKCS#11 v3.2 §5.1.6 <c>CKR_KEY_TYPE_INCONSISTENT</c> (§6.62.3 takes a generic
    /// secret or HKDF key).
    /// </summary>
    public const bool KryopticReportsAnHkdfBaseKeyOfTheWrongTypeAsInconsistent = false;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_RSA_PKCS_OAEP)</c> of a blob one byte short of the modulus answers
    /// <c>CKR_ENCRYPTED_DATA_INVALID</c> (<c>CKR_DEVICE_ERROR</c> before v1.5.5). PKCS#11 v3.2 §5.1.6 and §5.18.4:
    /// <c>CKR_WRAPPED_KEY_LEN_RANGE</c>.
    /// </summary>
    public const bool KryopticRefusesAnOaepBlobByItsLength = false;

    /// <summary>Gate for the RSA-OAEP wrapped-key length case: see <see cref="KryopticRefusesAnOaepBlobByItsLength"/>.</summary>
    public static bool OaepBlobLengthRefusalAvailable => KryopticAvailable && KryopticRefusesAnOaepBlobByItsLength;

    /// <summary>
    /// False while <c>C_DigestKey</c> of a key that is not a secret key (an EC private key) answers
    /// <c>CKR_KEY_HANDLE_INVALID</c>: <c>digest_key</c> in <c>src/fns/digest.rs</c>. PKCS#11 v3.2 §5.1.6:
    /// <c>CKR_KEY_INDIGESTIBLE</c> ("perhaps the key isn't a secret key"); the handle is a valid key's.
    /// </summary>
    public const bool KryopticReportsAPrivateKeyAsIndigestible = false;

    /// <summary>Gate for the private-key <c>C_DigestKey</c> case: see <see cref="KryopticReportsAPrivateKeyAsIndigestible"/>.</summary>
    public static bool PrivateKeyDigestRefusalAvailable => KryopticAvailable && KryopticReportsAPrivateKeyAsIndigestible;

    /// <summary>
    /// False while <c>C_Encrypt(CKM_AES_CTR)</c> of three blocks under <c>ulCounterBits</c> 2, the counter bits starting
    /// at 1, answers <c>CKR_DATA_LEN_RANGE</c>: the final step in <c>src/ossl/aes.rs</c> refuses once the blocks used
    /// reach <c>maxblocks</c> (<c>blockctr &gt;= maxblocks</c>), so the last counter value is never used. PKCS#11 v3.2
    /// §6.11.3: with that counter "only 3 blocks of data can be processed", and the fourth is
    /// <c>CKR_DATA_LEN_RANGE</c>. The out-of-range <c>ulCounterBits</c> rows pass.
    /// </summary>
    public const bool KryopticEncryptsTheLastCounterValue = false;

    /// <summary>Gate for the AES-CTR counter overflow case: see <see cref="KryopticEncryptsTheLastCounterValue"/>.</summary>
    public static bool AesCtrCounterOverflowAvailable => KryopticAvailable && KryopticEncryptsTheLastCounterValue;

    /// <summary>
    /// False while <c>C_SignInit(CKM_SHA256_RSA_PKCS_PSS)</c> with an <c>sLen</c> of 2^32 + 32 answers
    /// <c>CKR_GENERAL_ERROR</c>; a <c>hashAlg</c> other than the mechanism's is refused as it should be. PKCS#11 v3.2
    /// §6.1.15 (sLen at most k* - 2 - hLen) and §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>.
    /// </summary>
    public const bool KryopticRefusesAnOverlongPssSaltAsInvalid = false;

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_RSA_PKCS_OAEP)</c> with a NULL <c>pSourceData</c> behind <c>ulSourceDataLen</c>
    /// 8 answers <c>CKR_OK</c> and encrypts with the empty label (a probe's ciphertext decrypted under the default
    /// label): the NULL pointer becomes an empty vector. PKCS#11 v3.2 §6.1.7: the length "must be 0" when
    /// <c>pSourceData</c> is NULL; §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> (or <c>CKR_ARGUMENTS_BAD</c>).
    /// </summary>
    public const bool KryopticRefusesANullOaepLabel = false;

    /// <summary>Gate for the NULL OAEP label case: see <see cref="KryopticRefusesANullOaepLabel"/>.</summary>
    public static bool NullOaepLabelRefusalAvailable => KryopticAvailable && KryopticRefusesANullOaepLabel;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_CONCATENATE_BASE_AND_KEY)</c> ignores the second key's <c>CKA_ALLOWED_MECHANISMS</c>:
    /// a second key whose list leaves the mechanism out is concatenated anyway, and only the base key's list is
    /// checked. PKCS#11 v3.2 §4.8 Table 26: the list names the mechanisms "allowed to be used with this key",
    /// which we read as covering both keys of the derivation (BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced).
    /// </summary>
    public const bool KryopticChecksTheSecondKeysAllowedMechanisms = false;

    /// <summary>
    /// False while a one-byte key made from a sensitive, unextractable key can be digested:
    /// <c>CKM_EXTRACT_KEY_FROM_KEY</c> and <c>CKM_XOR_BASE_AND_DATA</c> with <c>CKA_VALUE_LEN</c> 1 make a sensitive
    /// key, as §6.43 requires, but <c>C_DigestKey</c> takes it, and its SHA-256 gives the byte away among 256
    /// candidates: a byte of the protected key per call. Refusing the one-byte derivation from a protected key, or
    /// the digest of a key made from one, would close it. After pkcs11-check's 1-byte recovery oracle
    /// (https://github.com/mingulov/pkcs11-check, test_misc_kdf.py, 0.3.1).
    /// </summary>
    public const bool KryopticKeepsAProtectedKeysBytesFromADigest = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> with SHA-256 and <c>CKA_VALUE_LEN</c> 8161 (255 x 32 + 1, past
    /// RFC 5869's limit) answers <c>CKR_DEVICE_ERROR</c>; 2^32 + 1 and a salt key that is no secret key are refused as
    /// they should be. PKCS#11 v3.2 §6.62.3 (RFC 5869), §4.1 and §5.1.6: <c>CKR_ATTRIBUTE_VALUE_INVALID</c>,
    /// <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// </summary>
    public const bool KryopticRefusesAnHkdfOutputAboveTheRfcLimit = false;

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
        _scratchDbPath = Path.Join(nativeDir, "kryoptic-scratch-token.sql");
        try { File.Delete(_scratchDbPath); } catch { /* best-effort */ }

        File.WriteAllText(_configPath,
            "[[slots]]\n" +
            $"slot = {SlotNumber}\n" +
            "dbtype = \"sqlite\"\n" +
            $"dbargs = \"{_dbPath.Replace("\\", "\\\\")}\"\n" +
            "\n[[slots]]\n" +
            $"slot = {ScratchSlotNumber}\n" +
            "dbtype = \"sqlite\"\n" +
            $"dbargs = \"{_scratchDbPath.Replace("\\", "\\\\")}\"\n");

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

            // The SO sets the user PIN (C_InitPIN on its login's own read/write session); disposing the login logs out.
            using (var soPin = new SecurePin(SoPin.Span))
            using (Pkcs11Login so = slot.Login(TokenUser.SecurityOfficer, soPin))
            using (var userPin = new SecurePin(UserPin.Span))
            {
                so.InitUserPinWithPin(userPin);
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
        try { if (_scratchDbPath.Length > 0) File.Delete(_scratchDbPath); } catch { /* best-effort */ }
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
