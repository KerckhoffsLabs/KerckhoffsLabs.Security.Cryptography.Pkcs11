using System.Runtime.InteropServices;
using System.Text.Json;
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
/// default, <c>swtpm-fips</c> with the profile a FIPS host allows, or <c>swtpm-min</c> with the fewest
/// algorithms), the TCG's reference implementation
/// (<c>tcgtpm</c>) or IBM's simulator (<c>ibmtpm</c>) behind the tpm2-abrmd resource manager,
/// or wolfTPM's fwtpm_server (<c>fwtpm</c>), reached directly. <see cref="SoftwareTpm"/> starts it, and
/// tpm2-abrmd and a D-Bus session bus for them where one is used, with the TPM's state in a temporary directory, so every run starts from a factory-state TPM and
/// leaves nothing behind.
/// tpm2-pkcs11 reaches it through the TCTI named by <c>TPM2_PKCS11_TCTI</c>, and keeps its token
/// metadata in a SQLite store in the directory named by <c>TPM2_PKCS11_STORE</c>, also temporary.
///
/// The library and the programs come from the tpm2-pkcs11 image (build/tpm2-pkcs11/Dockerfile),
/// which sets <see cref="Settings.Tpm2Pkcs11LibraryPath"/>, <see cref="Settings.SwtpmPath"/>,
/// <see cref="Settings.FwtpmPath"/>, <see cref="Settings.TcgTpmPath"/>, <see cref="Settings.IbmTpmPath"/>,
/// <see cref="Settings.Tpm2AbrmdPath"/> and
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

    /// <summary>
    /// Whether the TPM implements SHA-512, which a TPM needn't (the TCG reference implementation's default
    /// profile hasn't it): tpm2-pkcs11 lists <c>CKM_SHA512_HMAC</c> exactly when <c>TPM2_CAP_ALGS</c> has
    /// SHA-512. Without it the TPM can't decrypt RSA-OAEP with SHA-512, nor sign a SHA-512 digest with a
    /// P-521 key (whose order is longer than the digest, so tpm2-pkcs11 can't sign it as a shorter one).
    /// </summary>
    public bool TpmImplementsSha512 => Supports(CKM.CKM_SHA512_HMAC);

    /// <summary>
    /// Whether the TPM takes unpadded RSA (TPM2_RSA_Decrypt with the NULL scheme). tpm2-pkcs11 pads
    /// <c>CKM_RSA_PKCS</c> on the host and has the TPM apply the key with unpadded RSA, to sign (a DigestInfo too)
    /// and to decrypt, and needs it to sign PSS with a hash-length salt on a TPM that salts RSAPSS to the maximum.
    /// A TPM restricted to what a FIPS host allows (swtpm's <c>fips-host</c> profile) refuses unpadded RSA
    /// (libtpms's <c>no-unpadded-encryption</c>), and no capability says so, so this follows the TPM the
    /// fixture runs.
    /// </summary>
    public static bool TpmDoesUnpaddedRsa => TpmKind != SoftwareTpmKind.SwtpmFipsHost;

    /// <summary>
    /// Whether tpm2-pkcs11 decrypts PKCS#1 v1.5 on the TPM, which it does with unpadded RSA: every TPM here but
    /// one restricted to what a FIPS host allows (see <see cref="TpmDoesUnpaddedRsa"/>).
    /// </summary>
    public static bool TpmDecryptsPkcs1 => TpmDoesUnpaddedRsa;

    /// <summary>
    /// Whether the TPM's RSASSA signatures under SHA-512 are right: wolfTPM's fwTPM (v4.2.0 and master) puts the
    /// digest three bytes early in the PKCS#1 v1.5 block, so <c>CKM_SHA512_RSA_PKCS</c>, and <c>CKM_RSA_PKCS</c>
    /// over a SHA-512 DigestInfo (which tpm2-pkcs11 has the TPM sign), make signatures nothing verifies.
    /// </summary>
    public static bool TpmSignsRsassaSha512 => TpmKind is not (SoftwareTpmKind.Fwtpm);

    /// <summary>
    /// Whether the TPM signs an all-zero ECDSA digest (the empty message's, zero-padded), as ECDSA allows:
    /// wolfTPM's fwTPM (v4.2.0 and master) answers TPM_RC_FAILURE.
    /// </summary>
    public static bool TpmSignsZeroEcdsaDigest => TpmKind is not (SoftwareTpmKind.Fwtpm);

    /// <summary>Skips a case that needs unpadded RSA on the TPM: see <see cref="TpmDoesUnpaddedRsa"/>.</summary>
    internal static void SkipUnlessTpmDoesUnpaddedRsa()
    {
        if (!TpmDoesUnpaddedRsa)
            Assert.Skip("The TPM refuses unpadded RSA (a FIPS-host profile).");
    }

    /// <summary>Skips a case that decrypts PKCS#1 v1.5: see <see cref="TpmDecryptsPkcs1"/>.</summary>
    internal static void SkipUnlessTpmDecryptsPkcs1()
    {
        if (!TpmDecryptsPkcs1)
            Assert.Skip("The TPM has neither RSAES nor unpadded RSA (a FIPS-host profile), so it doesn't decrypt PKCS#1 v1.5.");
    }

    /// <summary>
    /// Skips a case on a NIST curve the token's <c>CKM_EC_KEY_PAIR_GEN</c> key-size range leaves out: tpm2-pkcs11
    /// states the range of the curves the TPM has, and a TPM needn't have P-521 (nor, on some, P-384).
    /// </summary>
    internal void SkipUnlessCurve(string curve) =>
        ((IPkcs11Backend)this).RequireKeySize(CKM.CKM_EC_KEY_PAIR_GEN, curve switch
        {
            "P-256" => 256UL,
            "P-384" => 384UL,
            "P-521" => 521UL,
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "A NIST curve name."),
        });

    /// <summary>Skips a case that needs the TPM's SHA-512: see <see cref="TpmImplementsSha512"/>.</summary>
    internal void SkipUnlessTpmImplementsSha512(bool needsIt)
    {
        if (needsIt && !TpmImplementsSha512)
            Assert.Skip("The TPM doesn't implement SHA-512 (TPM2_CAP_ALGS).");
    }

    private readonly SoftwareTpm? _tpm;
    private readonly string _storeDirectory = string.Empty;

    public static bool Tpm2Pkcs11Available =>
        OperatingSystem.IsLinux() &&
        Exists(Settings.Tpm2Pkcs11LibraryPath) && Exists(TpmPath) &&
        (TpmKind == SoftwareTpmKind.Fwtpm || (Exists(Settings.Tpm2AbrmdPath) && Exists(Settings.DbusDaemonPath)));

    /// <summary>The software TPM the fixture runs, from <see cref="Settings.Tpm2SoftwareTpm"/>.</summary>
    internal static SoftwareTpmKind TpmKind => Settings.Tpm2SoftwareTpm.ToLowerInvariant() switch
    {
        "fwtpm" => SoftwareTpmKind.Fwtpm,
        "swtpm-fips" => SoftwareTpmKind.SwtpmFipsHost,
        "swtpm-min" => SoftwareTpmKind.SwtpmMinimal,
        "tcgtpm" => SoftwareTpmKind.TcgReference,
        "ibmtpm" => SoftwareTpmKind.Ibm,
        _ => SoftwareTpmKind.Swtpm,
    };

    private static string? TpmPath => TpmKind switch
    {
        SoftwareTpmKind.Fwtpm => Settings.FwtpmPath,
        SoftwareTpmKind.TcgReference => Settings.TcgTpmPath,
        SoftwareTpmKind.Ibm => Settings.IbmTpmPath,
        _ => Settings.SwtpmPath,
    };

    private static bool Exists(string? path) => path is not null && File.Exists(path);

    // What tpm2-pkcs11 at the vendored commit (master a5156c5, after 1.10.1) doesn't do, or does wrong, that
    // the shared cases run into. Each flag is false while it stands, and its gate below skips the cases it
    // breaks; set it to true once fixed upstream.

    /// <summary>
    /// False while tpm2-pkcs11 maps a public key template's <c>CKA_VERIFY</c> onto the TPM key's decrypt
    /// attribute (<c>tpm_handlers</c> in src/lib/tpm.c: "Verify is same as decrypt"). A sign-only key pair,
    /// whose private template has <c>CKA_DECRYPT = false</c> as <see cref="Objects.PrivateKeyTemplateBuilder"/>
    /// writes by default, gets a TPM key without decrypt, so the <c>CKA_VERIFY</c> tpm2-pkcs11 then derives
    /// is false and contradicts the template: <c>C_GenerateKeyPair</c> answers <c>CKR_GENERAL_ERROR</c>
    /// ("User specified and TPM specified attr mismatch"). Verifying is a public-key operation and needs no
    /// TPM attribute. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11AcceptsSignOnlyKeyPairs = false;

    /// <summary>
    /// False while tpm2-pkcs11 doesn't map <c>CKA_DERIVE</c> onto the TPM key's decrypt attribute
    /// (tpm2-software/tpm2-pkcs11#663, open): an ECDH key pair, whose private template asks for derive only,
    /// gets a TPM key with neither sign nor decrypt, which the TPM refuses as inconsistent attributes.
    /// </summary>
    public const bool Tpm2Pkcs11AcceptsDeriveOnlyKeyPairs = false;

    /// <summary>
    /// False while tpm2-pkcs11's <c>C_GenerateKey</c> answers <c>CKR_FUNCTION_NOT_SUPPORTED</c> although
    /// its mechanism list has <c>CKM_AES_KEY_GEN</c> with <c>CKF_GENERATE</c>
    /// (tpm2-software/tpm2-pkcs11#564, open).
    /// </summary>
    public const bool Tpm2Pkcs11GeneratesSecretKeys = false;

    /// <summary>
    /// False while tpm2-pkcs11 makes token objects only: a key pair template with <c>CKA_TOKEN = false</c>
    /// is refused with <c>CKR_ATTRIBUTE_VALUE_INVALID</c> (tpm2-software/tpm2-pkcs11#921, open).
    /// </summary>
    public const bool Tpm2Pkcs11MakesSessionKeyPairs = false;

    /// <summary>
    /// False while a secret key created with <c>C_CreateObject</c> is accepted without the
    /// <c>CKA_ALLOWED_MECHANISMS</c> tpm2-pkcs11 needs to use it: every later operation on it answers
    /// <c>CKR_GENERAL_ERROR</c> ("Expected object to have: CKA_ALLOWED_MECHANISMS"), <c>C_DestroyObject</c>
    /// on it can answer <c>CKR_FUNCTION_FAILED</c>, and a 16-byte AES key reports a <c>CKA_VALUE_LEN</c> of
    /// 32. Related upstream: tpm2-software/tpm2-pkcs11#182 and #688 (open); this behaviour isn't reported.
    /// </summary>
    public const bool Tpm2Pkcs11UsesImportedSecretKeys = false;

    /// <summary>
    /// False while tpm2-pkcs11's <c>C_CreateObject</c> creates only RSA public keys and data objects
    /// ("Can only create RSA Public key objects or data objects"), so a private or EC key can't be imported.
    /// A documented limitation; key import goes through tpm2_ptool (tpm2-software/tpm2-pkcs11#861).
    /// </summary>
    public const bool Tpm2Pkcs11ImportsPrivateAndEcKeys = false;

    /// <summary>
    /// False while tpm2-pkcs11's software RSA <c>C_Encrypt</c> answers an output buffer too small for the
    /// ciphertext with <c>CKR_GENERAL_ERROR</c> ("output buffer too small", src/lib/ssl_util.c) instead of
    /// <c>CKR_BUFFER_TOO_SMALL</c> and the length it needs. The library starts with a buffer of the input's
    /// length, so every RSA encryption fails. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11ReportsEncryptLength = false;

    /// <summary>
    /// False while a <c>C_Decrypt</c> the TPM refuses (a ciphertext not below the modulus) leaves the
    /// decryption active: the next <c>C_DecryptInit</c> answers <c>CKR_OPERATION_ACTIVE</c>, where PKCS#11
    /// ends the operation on any result but <c>CKR_BUFFER_TOO_SMALL</c>. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11EndsAFailedDecrypt = false;

    /// <summary>
    /// False while tpm2-pkcs11 accepts a single-part <c>C_Digest</c> after <c>C_DigestUpdate</c> and returns
    /// <c>CKR_OK</c>, where every other backend refuses it. Not reported upstream.
    /// </summary>
    public const bool Tpm2Pkcs11RefusesSinglePartDigestAfterUpdate = false;

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
            if (Settings.Tpm2Pkcs11Backend.Equals("fapi", StringComparison.OrdinalIgnoreCase))
                UseFapi(_storeDirectory, _tpm.Tcti);

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

    /// <summary>
    /// Points tpm2-pkcs11 at its FAPI backend: a FAPI configuration for the fixture's TPM, with its keystore in
    /// <paramref name="directory"/> and no EK certificate (a software TPM has none), provisioned here with
    /// <c>Fapi_Provision</c> as <c>tss2_provision</c> would. tpm2-pkcs11 then keeps its tokens under the
    /// keystore's <c>/HS/SRK</c>.
    /// </summary>
    private static unsafe void UseFapi(string directory, string tcti)
    {
        string profiles = Settings.FapiProfileDirectory
            ?? throw new InvalidOperationException("PKCS11_TEST_FAPI_PROFILES names no FAPI profile directory.");
        string Dir(string name) => Directory.CreateDirectory(Path.Join(directory, name)).FullName;
        string config = Path.Join(directory, "fapi-config.json");
        File.WriteAllText(config, JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["profile_name"] = "P_ECCP256SHA256",
            ["profile_dir"] = profiles,
            ["user_dir"] = Dir("fapi-user"),
            ["system_dir"] = Dir("fapi-system"),
            ["log_dir"] = Dir("fapi-log"),
            ["tcti"] = tcti,
            ["system_pcrs"] = Array.Empty<int>(),
            ["ek_cert_less"] = "yes",
        }));
        SetEnv("TSS2_FAPICONF", config);

        IntPtr fapi = NativeLibrary.Load("libtss2-fapi.so.1");
        try
        {
            var initialize = (delegate* unmanaged<IntPtr*, byte*, uint>)NativeLibrary.GetExport(fapi, "Fapi_Initialize");
            var provision = (delegate* unmanaged<IntPtr, byte*, byte*, byte*, uint>)NativeLibrary.GetExport(fapi, "Fapi_Provision");
            var finalize = (delegate* unmanaged<IntPtr*, void>)NativeLibrary.GetExport(fapi, "Fapi_Finalize");

            IntPtr context = IntPtr.Zero;
            uint rc = initialize(&context, null);
            if (rc != 0)
                throw new InvalidOperationException($"Fapi_Initialize failed: TSS2_RC 0x{rc:X}.");
            rc = provision(context, null, null, null);
            finalize(&context);
            if (rc != 0)
                throw new InvalidOperationException($"Fapi_Provision failed: TSS2_RC 0x{rc:X}.");
        }
        finally
        {
            NativeLibrary.Free(fapi);
        }

        SetEnv("TPM2_PKCS11_BACKEND", "fapi");
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
