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

    /// <summary>
    /// False while <c>C_Logout</c> leaves the application's private session objects in place and readable: with
    /// nobody logged in, <c>C_GetAttributeValue</c> on one answers <c>CKR_OK</c>, and so does <c>C_EncryptInit</c>
    /// with the handle of a private token key, though <c>C_GetAttributeValue</c> on that handle answers
    /// <c>CKR_OBJECT_HANDLE_INVALID</c>. PKCS#11 v3.2 §5.6.10 destroys private session objects on <c>C_Logout</c>
    /// and makes every handle to a private object invalid.
    /// </summary>
    public const bool FreeHsmDestroysPrivateSessionObjectsOnLogout = false;

    /// <summary>
    /// False while the SO can make a private object: with the SO logged in, <c>C_CreateObject</c> with
    /// <c>CKA_PRIVATE = TRUE</c> succeeds, where PKCS#11 v3.2 §5.7.1 allows only public objects unless the normal
    /// user is logged in (<c>CKR_USER_NOT_LOGGED_IN</c>, §5.1.6).
    /// </summary>
    public const bool FreeHsmRefusesPrivateObjectsToTheSo = false;

    /// <summary>
    /// False while <c>C_CopyObject</c> in a read-only session copies a token object (template not naming
    /// <c>CKA_TOKEN</c>) into a new token object and answers <c>CKR_OK</c>. PKCS#11 v3.2 §5.7.2: only session
    /// objects can be created in a read-only session (<c>CKR_SESSION_READ_ONLY</c>).
    /// </summary>
    public const bool FreeHsmRefusesTokenObjectCopiesInReadOnlySessions = false;

    /// <summary>
    /// False while a sensitive RSA private key answers <c>C_GetAttributeValue</c> of <c>CKA_PRIVATE_EXPONENT</c>,
    /// <c>CKA_PRIME_1</c>, <c>CKA_PRIME_2</c>, <c>CKA_EXPONENT_1</c>, <c>CKA_EXPONENT_2</c> and <c>CKA_COEFFICIENT</c>
    /// with <c>CKR_ATTRIBUTE_TYPE_INVALID</c>, as if the key had no such attribute, where PKCS#11 v3.2 §5.7.5 has
    /// <c>CKR_ATTRIBUTE_SENSITIVE</c> for a value the key holds but may not reveal (§6.1.3, footnote 7). The
    /// value is not revealed: <c>ulValueLen</c> is <c>CK_UNAVAILABLE_INFORMATION</c>. A sensitive EC key's
    /// <c>CKA_VALUE</c> answers <c>CKR_ATTRIBUTE_SENSITIVE</c>.
    /// </summary>
    public const bool FreeHsmReportsRsaPrivatePartsAsSensitive = false;

    /// <summary>Gate for the SO private-object case: see <see cref="FreeHsmRefusesPrivateObjectsToTheSo"/>.</summary>
    public static bool SoPrivateObjectRefusalAvailable => FreeHsmAvailable && FreeHsmRefusesPrivateObjectsToTheSo;

    /// <summary>Gate for the C_Logout handle case: see <see cref="FreeHsmDestroysPrivateSessionObjectsOnLogout"/>.</summary>
    public static bool LogoutInvalidationAvailable => FreeHsmAvailable && FreeHsmDestroysPrivateSessionObjectsOnLogout;

    /// <summary>
    /// False while a key pair can be generated without the attribute that sizes it: <c>C_GenerateKeyPair</c> with
    /// <c>CKM_RSA_PKCS_KEY_PAIR_GEN</c> and no <c>CKA_MODULUS_BITS</c>, or <c>CKM_EC_KEY_PAIR_GEN</c> and no
    /// <c>CKA_EC_PARAMS</c>, answers <c>CKR_OK</c>, where PKCS#11 v3.2 §6.1.2 and §6.3.3 (footnote 3) say they
    /// must be given (§4.1.1 point 4: <c>CKR_TEMPLATE_INCOMPLETE</c>); and <c>C_CreateObject</c> of an EC private
    /// key without <c>CKA_EC_PARAMS</c> answers <c>CKR_TEMPLATE_INCONSISTENT</c>.
    /// </summary>
    public const bool FreeHsmRequiresTheKeyAttributes = false;

    /// <summary>
    /// False while a template's <c>CKA_CLASS</c> and <c>CKA_KEY_TYPE</c> are not checked against the mechanism or
    /// each other: <c>C_GenerateKey(CKM_AES_KEY_GEN)</c> with <c>CKK_GENERIC_SECRET</c> or <c>CKO_DATA</c>,
    /// <c>C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)</c> with <c>CKK_RSA</c> for the private key or
    /// <c>CKO_PRIVATE_KEY</c> for the public one, <c>C_CreateObject</c> of a <c>CKO_SECRET_KEY</c> of type
    /// <c>CKK_EC</c> or a <c>CKO_PRIVATE_KEY</c> of type <c>CKK_AES</c>, and <c>C_DeriveKey(CKM_HKDF_DERIVE)</c>
    /// with <c>CKO_DATA</c> all answer <c>CKR_OK</c>. PKCS#11 v3.2 §5.18.1, §5.18.2, §4.1.1 point 5 and §6.62.3:
    /// <c>CKR_TEMPLATE_INCONSISTENT</c>.
    /// </summary>
    public const bool FreeHsmChecksTheTemplatesClassAndKeyType = false;

    /// <summary>Gate for the inconsistent-template case: see <see cref="FreeHsmChecksTheTemplatesClassAndKeyType"/>.</summary>
    public static bool InconsistentTemplateRefusalAvailable => FreeHsmAvailable && FreeHsmChecksTheTemplatesClassAndKeyType;

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
