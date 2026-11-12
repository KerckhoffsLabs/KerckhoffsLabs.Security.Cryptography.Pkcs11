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
    // CKR_ENCRYPTED_DATA_INVALID. Single-part AES-GCM is unaffected. afchine1337/freehsm#35.
    public bool SupportsMultipartAesGcm => false;

    private const int SlotNumber = 0;

    private readonly string _stateDir = string.Empty;

    public static bool FreeHsmAvailable =>
        (Settings.FreeHsmLibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    /// <summary>
    /// False while a template's <c>CKA_CLASS</c> and <c>CKA_KEY_TYPE</c> are not checked against each other on key-pair
    /// generation and import: <c>C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)</c> with <c>CKK_RSA</c> for the private key or
    /// <c>CKO_PRIVATE_KEY</c> for the public one, and <c>C_CreateObject</c> of a <c>CKO_SECRET_KEY</c> of type
    /// <c>CKK_EC</c> or a <c>CKO_PRIVATE_KEY</c> of type <c>CKK_AES</c>, answer <c>CKR_OK</c>. PKCS#11 v3.2 §5.18.2 and
    /// §4.1.1 point 5: <c>CKR_TEMPLATE_INCONSISTENT</c>. v2.7.0 refuses the <c>C_GenerateKey</c> and
    /// <c>C_DeriveKey</c> rows.
    /// </summary>
    public const bool FreeHsmChecksKeyPairAndImportTemplates = false;

    /// <summary>The rows of the inconsistent-template case that <see cref="FreeHsmChecksKeyPairAndImportTemplates"/> covers.</summary>
    internal static bool IsKeyPairOrImportTemplateRow(string inconsistent) =>
        inconsistent is "EC key pair with an RSA private key" or "EC key pair with a private-key class for the public key"
            or "secret key of type CKK_EC" or "private key of type CKK_AES";

    /// <summary>
    /// False while <c>C_CreateObject</c> of an EC private key without <c>CKA_EC_PARAMS</c> answers
    /// <c>CKR_TEMPLATE_INCONSISTENT</c>, where PKCS#11 v3.2 §6.3.4 says the attribute must be given (§4.1.1 point 4:
    /// <c>CKR_TEMPLATE_INCOMPLETE</c>). Nothing is created. v2.7.0 answers <c>CKR_TEMPLATE_INCOMPLETE</c> for key-pair
    /// generation without <c>CKA_MODULUS_BITS</c> or <c>CKA_EC_PARAMS</c>.
    /// </summary>
    public const bool FreeHsmReportsAnEcPrivateKeyWithoutParamsAsIncomplete = false;

    /// <summary>
    /// False while <c>C_CopyObject</c> of an AES key with a new <c>CKA_VALUE</c> is refused with
    /// <c>CKR_TEMPLATE_INCONSISTENT</c>. PKCS#11 v3.2 §4.1.3 and §4.1.1 point 3: <c>CKR_ATTRIBUTE_READ_ONLY</c>. The
    /// value is not changed, and <c>C_SetAttributeValue</c> of key material answers <c>CKR_ATTRIBUTE_READ_ONLY</c>.
    /// </summary>
    public const bool FreeHsmRefusesNewKeyMaterialInACopyAsReadOnly = false;

    /// <summary>
    /// False while a data object's <c>CKA_OBJECT_ID</c> is refused: <c>C_CreateObject</c> with it answers
    /// <c>CKR_ATTRIBUTE_TYPE_INVALID</c> (v2.7.0; earlier versions took it and dropped it). PKCS#11 v3.2 Table 20 gives
    /// every data object a <c>CKA_OBJECT_ID</c> (default empty). <c>CKA_VALUE</c> and <c>CKA_APPLICATION</c> are kept
    /// and copied.
    /// </summary>
    public const bool FreeHsmKeepsCkaObjectId = false;

    /// <summary>Gate for the data object copy case: see <see cref="FreeHsmKeepsCkaObjectId"/>.</summary>
    public static bool DataObjectIdAvailable => FreeHsmAvailable && FreeHsmKeepsCkaObjectId;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> on P-256 refuses a peer value that is no point (1 KiB, or a DER
    /// length that lies) with <c>CKR_ATTRIBUTE_VALUE_INVALID</c>: the peer value is a mechanism parameter, so PKCS#11
    /// v3.2 §6.3.16 and §5.1.6 make it <c>CKR_MECHANISM_PARAM_INVALID</c>. No key is made. v2.7.0 refuses
    /// <c>CKD_NULL</c> with shared data and a <c>CKA_VALUE_LEN</c> above the secret as specified.
    /// afchine1337/freehsm#37 (E1).
    /// </summary>
    public const bool FreeHsmRefusesABadEcdhPeerAsAParameter = false;

    /// <summary>
    /// False while a private key gets every usage of its class that the template does not turn off: an Edwards key
    /// unwrapped with <c>CKA_SIGN</c> alone reports <c>CKA_DERIVE = TRUE</c>, and a Montgomery key unwrapped with
    /// <c>CKA_DERIVE</c> alone reports <c>CKA_SIGN = TRUE</c> (<c>fhsm_compute_usage</c> in <c>src/fhsm_pkcs11.c</c>
    /// starts every <c>CKO_PRIVATE_KEY</c> from decrypt, sign, unwrap and derive). PKCS#11 v3.2 defaults
    /// <c>CKA_DERIVE</c> to FALSE. <c>C_GenerateKeyPair</c> clears it for Edwards keys only, so a generated P-256 or
    /// X25519 key has the same extra usage; the unwrap path clears nothing. afchine1337/freehsm#34.
    /// </summary>
    public const bool FreeHsmGrantsAnUnwrappedKeyOnlyTheUsageAsked = false;

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
