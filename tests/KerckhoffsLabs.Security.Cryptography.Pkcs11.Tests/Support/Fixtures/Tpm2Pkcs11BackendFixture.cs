using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping tpm2-pkcs11 (tpm2-software/tpm2-pkcs11), the PKCS#11 interface to
/// a TPM 2.0 — another fully independent real backend alongside SoftHSM2, opencryptoki, NSS softoken,
/// Kryoptic, BouncyHsm and Craton HSM, and the only one whose keys live in a TPM: it wraps every key under
/// the TPM's storage hierarchy and runs RSA, ECDSA and HMAC on the TPM, through tpm2-tss.
///
/// The TPM is a software one, private to the fixture, as <c>PKCS11_TEST_TPM</c> chooses: swtpm (the
/// default) behind the tpm2-abrmd resource manager, or wolfTPM's fwtpm_server (<c>fwtpm</c>), reached
/// directly. <see cref="SoftwareTpm"/> starts it, and for swtpm tpm2-abrmd and a D-Bus session bus for
/// them, with the TPM's state in a temporary directory, so every run starts from a factory-state TPM and
/// leaves nothing behind.
/// tpm2-pkcs11 reaches it through the TCTI named by <c>TPM2_PKCS11_TCTI</c>, and keeps its token
/// metadata in a SQLite store in the directory named by <c>TPM2_PKCS11_STORE</c>, also temporary.
///
/// The library and the programs come from the tpm2-pkcs11 image (build/tpm2-pkcs11/Dockerfile),
/// which sets <see cref="Settings.Tpm2Pkcs11LibraryPath"/>, <see cref="Settings.SwtpmPath"/>,
/// <see cref="Settings.FwtpmPath"/>, <see cref="Settings.Tpm2AbrmdPath"/> and
/// <see cref="Settings.DbusDaemonPath"/>; the tests run inside
/// it in CI. Elsewhere the variables are unset and the tests skip. Linux-only, like the image.
///
/// Like Kryoptic, tpm2-pkcs11 implements <c>C_InitToken</c>/<c>C_InitPIN</c>: initializing the empty
/// token it presents in a fresh store creates the TPM primary key it wraps everything under, so the
/// token is provisioned through the library under test and tpm2_ptool isn't needed.
/// </summary>
public sealed class Tpm2Pkcs11BackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = "tpm2-so-1234"u8.ToArray();
    public ReadOnlyMemory<byte> UserPin { get; } = "tpm2-user-1234"u8.ToArray();
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when tpm2-pkcs11 is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    private readonly SoftwareTpm? _tpm;
    private readonly string _storeDirectory = string.Empty;

    public static bool Tpm2Pkcs11Available =>
        OperatingSystem.IsLinux() &&
        Exists(Settings.Tpm2Pkcs11LibraryPath) && Exists(TpmPath) &&
        (TpmKind == SoftwareTpmKind.Fwtpm || (Exists(Settings.Tpm2AbrmdPath) && Exists(Settings.DbusDaemonPath)));

    /// <summary>The software TPM the fixture runs, from <see cref="Settings.Tpm2SoftwareTpm"/>.</summary>
    internal static SoftwareTpmKind TpmKind =>
        Settings.Tpm2SoftwareTpm.Equals("fwtpm", StringComparison.OrdinalIgnoreCase) ? SoftwareTpmKind.Fwtpm : SoftwareTpmKind.Swtpm;

    private static string? TpmPath => TpmKind == SoftwareTpmKind.Fwtpm ? Settings.FwtpmPath : Settings.SwtpmPath;

    private static bool Exists(string? path) => path is not null && File.Exists(path);

    // What tpm2-pkcs11 doesn't do, or does wrong, that the shared cases run into. Each flag is false while
    // it stands, and its gate below skips the cases it breaks. vendor/tpm2-pkcs11 is the fork branch
    // AlexLaroche/tpm2-pkcs11 feat/pkcs11-3.x (1.10.1 and later master, plus PKCS#11 v3.x and fixes); the
    // flags it fixes are true, and keep what 1.10.1 does, for when the submodule goes back to a release.

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11 maps a public key template's <c>CKA_VERIFY</c> onto the TPM key's decrypt
    /// attribute (<c>tpm_handlers</c> in src/lib/tpm.c: "Verify is same as decrypt"). A sign-only key pair,
    /// whose private template has <c>CKA_DECRYPT = false</c> as <see cref="Objects.PrivateKeyTemplateBuilder"/>
    /// writes by default, gets a TPM key without decrypt, so the <c>CKA_VERIFY</c> tpm2-pkcs11 then derives
    /// is false and contradicts the template: <c>C_GenerateKeyPair</c> answers <c>CKR_GENERAL_ERROR</c>
    /// ("User specified and TPM specified attr mismatch"). Verifying is a public-key operation and needs no
    /// TPM attribute. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11AcceptsSignOnlyKeyPairs = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11 doesn't map <c>CKA_DERIVE</c> onto the TPM key's decrypt attribute
    /// (tpm2-software/tpm2-pkcs11#663, open): an ECDH key pair, whose private template asks for derive only,
    /// gets a TPM key with neither sign nor decrypt, which the TPM refuses as inconsistent attributes.
    /// </summary>
    public const bool Tpm2Pkcs11AcceptsDeriveOnlyKeyPairs = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11's <c>C_GenerateKey</c> answers <c>CKR_FUNCTION_NOT_SUPPORTED</c> although
    /// its mechanism list has <c>CKM_AES_KEY_GEN</c> with <c>CKF_GENERATE</c>
    /// (tpm2-software/tpm2-pkcs11#564, open).
    /// </summary>
    public const bool Tpm2Pkcs11GeneratesSecretKeys = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11 makes token objects only: a key pair template with <c>CKA_TOKEN = false</c>
    /// is refused with <c>CKR_ATTRIBUTE_VALUE_INVALID</c> (tpm2-software/tpm2-pkcs11#921, open).
    /// </summary>
    public const bool Tpm2Pkcs11MakesSessionKeyPairs = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while a secret key created with <c>C_CreateObject</c> is accepted without the
    /// <c>CKA_ALLOWED_MECHANISMS</c> tpm2-pkcs11 needs to use it: every later operation on it answers
    /// <c>CKR_GENERAL_ERROR</c> ("Expected object to have: CKA_ALLOWED_MECHANISMS"), <c>C_DestroyObject</c>
    /// on it can answer <c>CKR_FUNCTION_FAILED</c>, and a 16-byte AES key reports a <c>CKA_VALUE_LEN</c> of
    /// 32. Related upstream: tpm2-software/tpm2-pkcs11#182 and #688 (open); this behaviour isn't reported.
    /// </summary>
    public const bool Tpm2Pkcs11UsesImportedSecretKeys = true;

    /// <summary>
    /// False while tpm2-pkcs11's <c>C_CreateObject</c> creates only RSA public keys and data objects
    /// ("Can only create RSA Public key objects or data objects"), so a private or EC key can't be imported.
    /// A documented limitation; key import goes through tpm2_ptool (tpm2-software/tpm2-pkcs11#861).
    /// </summary>
    public const bool Tpm2Pkcs11ImportsPrivateAndEcKeys = false;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11's software RSA <c>C_Encrypt</c> answers an output buffer too small for the
    /// ciphertext with <c>CKR_GENERAL_ERROR</c> ("output buffer too small", src/lib/ssl_util.c) instead of
    /// <c>CKR_BUFFER_TOO_SMALL</c> and the length it needs. The library starts with a buffer of the input's
    /// length, so every RSA encryption fails. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11ReportsEncryptLength = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while a <c>C_Decrypt</c> the TPM refuses (a ciphertext not below the modulus) leaves the
    /// decryption active: the next <c>C_DecryptInit</c> answers <c>CKR_OPERATION_ACTIVE</c>, where PKCS#11
    /// ends the operation on any result but <c>CKR_BUFFER_TOO_SMALL</c>. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11EndsAFailedDecrypt = true;

    /// <summary>
    /// True: fixed on the fork. False in 1.10.1, while tpm2-pkcs11 accepts a single-part <c>C_Digest</c> after <c>C_DigestUpdate</c> and returns
    /// <c>CKR_OK</c>, where every other backend refuses it. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11RefusesSinglePartDigestAfterUpdate = true;

    /// <summary>
    /// False: a TPM decrypts RSA-OAEP only with a label that ends with a zero byte (TPM 2.0 Part 3,
    /// TPM2_RSA_Decrypt; libtpms's <c>IsLabelProperlyFormatted</c>), so tpm2-pkcs11 refuses any other label
    /// with <c>CKR_MECHANISM_PARAM_INVALID</c>. A limitation of the TPM, not of tpm2-pkcs11.
    /// </summary>
    public const bool Tpm2DecryptsOaepWithAnyLabel = false;

    /// <summary>
    /// False: tpm2-pkcs11 keeps an ECDH-derived secret as the <c>CKA_VALUE</c> of a <c>CKK_GENERIC_SECRET</c>,
    /// not as a TPM key, so it refuses a derived key of another type (an AES key) with
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>; and it has no AES-GCM to use one with.
    /// </summary>
    public const bool Tpm2Pkcs11DerivesAesKeys = false;

    /// <summary>
    /// False: tpm2-pkcs11 has no key-wrapping mechanism (<c>C_WrapKey</c>/<c>C_UnwrapKey</c> answer
    /// <c>CKR_FUNCTION_NOT_SUPPORTED</c>), so it refuses a key template with <c>CKA_WRAP</c> or
    /// <c>CKA_UNWRAP</c> set, with <c>CKR_ATTRIBUTE_VALUE_INVALID</c>.
    /// </summary>
    public const bool Tpm2Pkcs11WrapsKeys = false;

    /// <summary>
    /// False: a TPM holds at most 128 bytes of key (<c>MAX_SYM_DATA</c>, TPM 2.0 Part 2), so tpm2-pkcs11
    /// refuses to import a longer HMAC key, RFC 4231's 131-byte one say, with <c>CKR_ATTRIBUTE_VALUE_INVALID</c>.
    /// A limitation of the TPM.
    /// </summary>
    public const bool Tpm2HoldsKeysOver128Bytes = false;

    /// <summary>Gate for cases that import an HMAC key over 128 bytes: see <see cref="Tpm2HoldsKeysOver128Bytes"/>.</summary>
    public static bool LongHmacKeysAvailable => ImportedSecretKeysAvailable && Tpm2HoldsKeysOver128Bytes;

    /// <summary>Gate for cases that generate a key-wrapping key: see <see cref="Tpm2Pkcs11WrapsKeys"/>.</summary>
    public static bool KeyWrappingAvailable => SecretKeyGenerationAvailable && Tpm2Pkcs11WrapsKeys;

    /// <summary>Gate for cases that decrypt RSA-OAEP with an arbitrary label: see <see cref="Tpm2DecryptsOaepWithAnyLabel"/>.</summary>
    public static bool OaepAnyLabelAvailable => SessionKeyPairsAvailable && Tpm2DecryptsOaepWithAnyLabel;

    /// <summary>Gate for cases that derive an AES key with ECDH: see <see cref="Tpm2Pkcs11DerivesAesKeys"/>.</summary>
    public static bool DerivedAesKeysAvailable => SessionKeyPairsAvailable && Tpm2Pkcs11DerivesAesKeys;

    /// <summary>Gate for cases that generate a sign-only key pair: see <see cref="Tpm2Pkcs11AcceptsSignOnlyKeyPairs"/>.</summary>
    public static bool SignOnlyKeyPairsAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11AcceptsSignOnlyKeyPairs;

    /// <summary>Gate for cases that generate an ECDH key pair: see <see cref="Tpm2Pkcs11AcceptsDeriveOnlyKeyPairs"/>.</summary>
    public static bool DeriveOnlyKeyPairsAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11AcceptsDeriveOnlyKeyPairs;

    /// <summary>Gate for cases that generate a secret key: see <see cref="Tpm2Pkcs11GeneratesSecretKeys"/>.</summary>
    public static bool SecretKeyGenerationAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11GeneratesSecretKeys;

    /// <summary>Gate for cases that generate a session key pair: see <see cref="Tpm2Pkcs11MakesSessionKeyPairs"/>.</summary>
    public static bool SessionKeyPairsAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11MakesSessionKeyPairs;

    /// <summary>Gate for cases that import a secret key: see <see cref="Tpm2Pkcs11UsesImportedSecretKeys"/>.</summary>
    public static bool ImportedSecretKeysAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11UsesImportedSecretKeys;

    /// <summary>Gate for cases that import a private or EC key: see <see cref="Tpm2Pkcs11ImportsPrivateAndEcKeys"/>.</summary>
    public static bool PrivateAndEcKeyImportAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11ImportsPrivateAndEcKeys;

    /// <summary>Gate for cases that encrypt with RSA: see <see cref="Tpm2Pkcs11ReportsEncryptLength"/>.</summary>
    public static bool RsaEncryptionAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11ReportsEncryptLength;

    /// <summary>Gate for cases that decrypt again after a refused decryption: see <see cref="Tpm2Pkcs11EndsAFailedDecrypt"/>.</summary>
    public static bool FailedDecryptEndsAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11EndsAFailedDecrypt;

    /// <summary>Gate for the single-part-after-update digest case: see <see cref="Tpm2Pkcs11RefusesSinglePartDigestAfterUpdate"/>.</summary>
    public static bool DigestMixingRefusalAvailable => Tpm2Pkcs11Available && Tpm2Pkcs11RefusesSinglePartDigestAfterUpdate;

    public Tpm2Pkcs11BackendFixture()
    {
        if (!Tpm2Pkcs11Available)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = Settings.Tpm2Pkcs11LibraryPath!;
        _tpm = SoftwareTpm.Start(TpmKind, TpmPath!, Settings.DbusDaemonPath!, Settings.Tpm2AbrmdPath!);
        try
        {
            _storeDirectory = Directory.CreateTempSubdirectory("kl-tpm2-pkcs11-").FullName;

            // tpm2-pkcs11 reads these at C_Initialize time; as for Kryoptic, .NET's
            // Environment.SetEnvironmentVariable does not reach native getenv() on Linux, so setenv() too.
            // A log level of 0 keeps its error messages for refused operations, which the tests provoke
            // on purpose, off the test output; set TPM2_PKCS11_LOG_LEVEL (1 to 2) to see them.
            SetEnv("DBUS_SESSION_BUS_ADDRESS", _tpm.BusAddress);
            SetEnv("TPM2_PKCS11_TCTI", _tpm.Tcti);
            SetEnv("TPM2_PKCS11_STORE", _storeDirectory);
            SetEnv("TPM2_PKCS11_LOG_LEVEL", Environment.GetEnvironmentVariable("TPM2_PKCS11_LOG_LEVEL") ?? "0");

            Library = Pkcs11Library.Load(LibraryPath);
            try
            {
                Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault()
                    ?? throw new InvalidOperationException("tpm2-pkcs11 presented no slot for its empty store.");

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
        catch
        {
            _tpm.Dispose();
            DeleteStore();
            throw;
        }
    }

    private static void SetEnv(string name, string value)
    {
        Environment.SetEnvironmentVariable(name, value);
        KryopticBackendFixture.SetNativeEnv(name, value);
    }

    public void Dispose()
    {
        Library?.Dispose();
        _tpm?.Dispose();
        DeleteStore();
    }

    private void DeleteStore()
    {
        if (_storeDirectory.Length == 0) return;
        try
        {
            Directory.Delete(_storeDirectory, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: it is a temporary directory.
        }
    }
}

/// <summary>xUnit collection definition for the tpm2-pkcs11 backend.</summary>
[CollectionDefinition("Tpm2Pkcs11")]
public sealed class Tpm2Pkcs11BackendCollection : ICollectionFixture<Tpm2Pkcs11BackendFixture>
{ }
