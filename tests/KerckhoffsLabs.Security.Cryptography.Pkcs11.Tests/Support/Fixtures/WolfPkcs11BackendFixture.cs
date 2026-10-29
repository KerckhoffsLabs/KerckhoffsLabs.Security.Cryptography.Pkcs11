using System.Reflection;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping wolfPKCS11 — another fully independent real PKCS#11 implementation
/// alongside SoftHSM2, opencryptoki, NSS softoken, Kryoptic, BouncyHsm, Craton HSM and FreeHSM. A C
/// PKCS#11 v3.2 module on wolfCrypt, with ML-KEM and ML-DSA, used here with its own file-based software
/// token (not its wolfTPM backend).
///
/// Uses the library built from the vendor/wolfpkcs11 and vendor/wolfssl submodules and placed next to the
/// test assembly by the BuildWolfPkcs11 MSBuild target; <see cref="Settings.WolfPkcs11LibraryPath"/> may
/// override the path for local debugging. Linux-only for now (see build-wolfpkcs11.sh).
///
/// Like FreeHSM, wolfPKCS11 implements <c>C_InitToken</c>/<c>C_InitPIN</c>, so the token is provisioned
/// through the library under test. Its token store goes to a fresh owner-only temporary directory named by
/// <c>WOLFPKCS11_TOKEN_PATH</c>, so every run starts from a factory-state token, leaves nothing behind and
/// never touches the default <c>~/.wolfPKCS11</c>.
/// </summary>
public sealed class WolfPkcs11BackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when wolfPKCS11 is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>The directory named by <c>WOLFPKCS11_TOKEN_PATH</c>, where the module keeps its token.</summary>
    internal string TokenDirectory { get; } = string.Empty;

    public static bool WolfPkcs11Available =>
        (Settings.WolfPkcs11LibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    // What wolfPKCS11 at the vendored commit (v2.2.0) does differently from PKCS#11 v3.2 that the shared
    // cases run into. Each flag is false while it stands, a gate or a wrapper check skips the cases it
    // breaks, and the matching WolfPkcs11QuirkTests tripwire fails once it is fixed: set the flag to true
    // then and delete the tripwire.

    /// <summary>
    /// False while <c>C_DeriveKey</c> overrides the template's <c>CKA_SENSITIVE</c> and <c>CKA_EXTRACTABLE</c>
    /// from the base key: a sensitive base gives a sensitive key and a non-extractable base a non-extractable
    /// one, whatever the template asks, so the value of an ECDH secret or an HKDF output cannot be read back.
    /// For <c>CKM_ECDH1_DERIVE</c> (§6.3.17) and <c>CKM_HKDF_DERIVE</c> (§6.62.3) the template may set either
    /// value; the base key decides only <c>CKA_ALWAYS_SENSITIVE</c> and <c>CKA_NEVER_EXTRACTABLE</c>.
    /// </summary>
    public const bool WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity = false;

    /// <summary>
    /// False while RSA-OAEP refuses an empty message: <c>C_Encrypt</c> of zero bytes gives
    /// <c>CKR_FUNCTION_FAILED</c> and <c>C_Decrypt</c> of another implementation's ciphertext of it
    /// <c>CKR_ENCRYPTED_DATA_INVALID</c>, though RFC 8017 §7.1 allows any length up to k - 2hLen - 2.
    /// </summary>
    public const bool WolfPkcs11AcceptsEmptyOaepMessage = false;

    /// <summary>
    /// False while <c>C_Verify</c> answers a malformed or out-of-range signature with <c>CKR_FUNCTION_FAILED</c>
    /// instead of <c>CKR_SIGNATURE_INVALID</c>, so the caller cannot tell a bad signature from a failing token:
    /// every altered PKCS#1 v1.5 RSA signature, an RSA-PSS one at or above the modulus, an ECDSA P-521 one
    /// whose r or s has a bit above the 521st set, and an ML-DSA one whose hint encoding is malformed (FIPS 204
    /// §7.3 rejects it like any other invalid signature). Correctly encoded wrong signatures get
    /// <c>CKR_SIGNATURE_INVALID</c>. Which one a one-bit flip gives depends on the bit and the signature, so
    /// the cases that alter a signature would fail at random.
    /// </summary>
    public const bool WolfPkcs11RejectsMalformedSignatures = false;

    /// <summary>
    /// False while <c>C_Verify</c> answers an RSA signature of the wrong length (empty, cut short or padded,
    /// PSS and PKCS#1 v1.5 alike) with <c>CKR_FUNCTION_FAILED</c> instead of <c>CKR_SIGNATURE_LEN_RANGE</c>.
    /// </summary>
    public const bool WolfPkcs11RejectsWrongLengthRsaSignatures = false;

    /// <summary>
    /// False while <c>CKM_RSA_PKCS_KEY_PAIR_GEN</c> advertises 1024 bits as its minimum (a constant in
    /// <c>src/slot.c</c>) but fails to make a 1024-bit key with <c>CKR_FUNCTION_FAILED</c>: wolfSSL's default
    /// <c>RSA_MIN_SIZE</c> is 2048.
    /// </summary>
    public const bool WolfPkcs11GeneratesItsMinimumRsaKeySize = false;

    /// <summary>
    /// False while <c>CKA_WRAP_TEMPLATE</c> and <c>CKA_UNWRAP_TEMPLATE</c> make <c>C_GenerateKey</c> fail with
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>: wolfPKCS11 lists them as byte arrays (<c>src/crypto.c</c>) rather
    /// than the attribute arrays PKCS#11 v3.2 §4.11 defines, so no key-encryption key with a template can be
    /// made, and <see cref="Pkcs11Session.GenerateAesKeyEncryptionKey"/> fails.
    /// </summary>
    public const bool WolfPkcs11AcceptsWrapTemplates = false;

    /// <summary>
    /// A capability, not a departure from PKCS#11: false while wolfPKCS11 wraps and unwraps only RSA private
    /// keys and AES, generic-secret and HKDF keys (<c>CHECK_WRAPPABLE</c> in <c>src/crypto.c</c>), so an EC
    /// private key cannot be unwrapped (<c>CKR_KEY_NOT_WRAPPABLE</c>). No mechanism flag says so.
    /// </summary>
    public const bool WolfPkcs11UnwrapsEcPrivateKeys = false;

    /// <summary>
    /// False while a session object is visible only to the session that made it: wolfPKCS11 keeps session
    /// objects per session, so another session of the application finds nothing and its handle is invalid
    /// there. PKCS#11 v3.2 §5.6.2 (<c>C_CloseSession</c>) has a session object used by the application's other
    /// sessions until the session that made it closes.
    /// </summary>
    public const bool WolfPkcs11SharesSessionObjectsAcrossSessions = false;

    /// <summary>
    /// False while the hash-and-sign mechanisms (every <c>CKM_SHA*_RSA_PKCS</c>, <c>CKM_SHA*_RSA_PKCS_PSS</c>
    /// and <c>CKM_ECDSA_SHA*</c>) and AES-ECB encryption work single-part only: <c>C_SignUpdate</c>,
    /// <c>C_VerifyUpdate</c> and <c>C_EncryptUpdate</c> return <c>CKR_MECHANISM_INVALID</c>, though PKCS#11 v3.2
    /// defines them multi-part and the token advertises them for <c>CKF_SIGN</c>, <c>CKF_VERIFY</c> and
    /// <c>CKF_ENCRYPT</c>. AES-CBC, AES-GCM, AES-CTS, CMAC and the HMACs work multi-part.
    /// </summary>
    public const bool WolfPkcs11DoesMultipartSignAndEcb = false;

    /// <summary>
    /// False while <c>C_GetAttributeValue</c> with a buffer too small for the value returns
    /// <c>CKR_BUFFER_TOO_SMALL</c> but leaves the attribute's <c>ulValueLen</c> as the caller gave it, where
    /// PKCS#11 v3.2 §5.7.5 sets it to <c>CK_UNAVAILABLE_INFORMATION</c>: a caller cannot tell which attribute
    /// was short.
    /// </summary>
    public const bool WolfPkcs11MarksAShortBufferUnavailable = false;

    /// <summary>
    /// False while <c>C_CreateObject</c> makes a <c>CKO_PRIVATE_KEY</c> of the secret key type <c>CKK_AES</c>: the
    /// template is taken with <c>CKR_OK</c>, where PKCS#11 v3.2 §4.1.1 point 5 refuses a set of values that cannot
    /// hold together (<c>CKR_TEMPLATE_INCONSISTENT</c>). A <c>CKO_SECRET_KEY</c> of type <c>CKK_EC</c> is refused.
    /// Fixed upstream after v2.2.0 (wolfSSL/wolfPKCS11#263 checks the class against the key type).
    /// WolfPkcs11QuirkTests.PrivateKeyOfASecretKeyType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11RefusesAPrivateKeyOfASecretKeyType = false;

    /// <summary>
    /// False while <c>C_VerifyRecover</c>, with another operation active and no verification with recovery,
    /// answers <c>CKR_MECHANISM_INVALID</c> where PKCS#11 v3.2 §5.15.6 and §5.2 give
    /// <c>CKR_OPERATION_NOT_INITIALIZED</c>: it reads the session's one active mechanism (an ECDSA
    /// <c>C_SignInit</c>'s, say) and refuses it before it asks whether a verify-recover was started
    /// (<c>wp11_C_VerifyRecover</c> in <c>src/crypto.c</c>). With nothing active it answers correctly.
    /// WolfPkcs11QuirkTests.VerifyRecoverUnderASign_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11ReportsAVerifyRecoverNeverStarted = false;

    /// <summary>
    /// False while a single-part <c>CKM_AES_CBC_PAD</c> <c>C_Decrypt</c> into a buffer too small for the plaintext
    /// answers <c>CKR_BUFFER_TOO_SMALL</c> with the length of the blocks before the last one only (32 for a
    /// 48-byte ciphertext of 43 bytes of plaintext): <c>WP11_AesCbcPad_Decrypt</c> in <c>src/internal.c</c> reports
    /// what its update step needs, before the final block. PKCS#11 v3.2 §5.2: "at least the number of bytes
    /// needed". It writes nothing past the buffer.
    /// WolfPkcs11QuirkTests.CbcPadDecryptShortBuffer_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11ReportsTheWholeCbcPadPlaintextLength = false;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_AES_KEY_WRAP)</c> of a blob that is not a whole number of semiblocks (20 bytes)
    /// answers <c>CKR_WRAPPED_KEY_INVALID</c>: <c>C_UnwrapKey</c> in <c>src/crypto.c</c> maps the
    /// <c>CKR_ENCRYPTED_DATA_INVALID</c> its <c>C_Decrypt</c> gives (a code §5.10.2 allows there) to it. PKCS#11 v3.2
    /// §5.1.6: a wrapped key invalid by its length alone is <c>CKR_WRAPPED_KEY_LEN_RANGE</c>, which outranks
    /// <c>CKR_WRAPPED_KEY_INVALID</c>. An 8-byte blob is refused as it should be.
    /// WolfPkcs11QuirkTests.KeyWrapBlobOfAPartialSemiblock_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11RefusesAKeyWrapBlobByItsLength = false;

    /// <summary>
    /// False while <c>C_Verify(CKM_RSA_X_509)</c> with more data than the modulus has bytes answers
    /// <c>CKR_FUNCTION_FAILED</c> (wolfPKCS11's own test expects it). PKCS#11 v3.2 §6.1.12 (Table 45: at most k
    /// bytes) and §5.1.6: <c>CKR_DATA_LEN_RANGE</c>. The token key verifies the right data afterwards.
    /// WolfPkcs11QuirkTests.OverlongRawRsaVerify_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11RefusesOverlongRawRsaDataByItsLength = false;

    /// <summary>Gate for cases that read back a derived key: see <see cref="WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity"/>.</summary>
    public static bool DerivedKeyReadbackAvailable => WolfPkcs11Available && WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity;

    /// <summary>Gate for cases that verify an altered signature: see <see cref="WolfPkcs11RejectsMalformedSignatures"/>.</summary>
    public static bool MalformedSignatureRejectionAvailable => WolfPkcs11Available && WolfPkcs11RejectsMalformedSignatures;

    /// <summary>Gate for cases that make a key with a wrap or unwrap template: see <see cref="WolfPkcs11AcceptsWrapTemplates"/>.</summary>
    public static bool WrapTemplateAvailable => WolfPkcs11Available && WolfPkcs11AcceptsWrapTemplates;

    /// <summary>Gate for cases that unwrap an EC private key: see <see cref="WolfPkcs11UnwrapsEcPrivateKeys"/>.</summary>
    public static bool EcPrivateKeyUnwrapAvailable => WolfPkcs11Available && WolfPkcs11UnwrapsEcPrivateKeys;

    /// <summary>Gate for cases that use a session object from another session: see <see cref="WolfPkcs11SharesSessionObjectsAcrossSessions"/>.</summary>
    public static bool SharedSessionObjectsAvailable => WolfPkcs11Available && WolfPkcs11SharesSessionObjectsAcrossSessions;

    /// <summary>Gate for the short-buffer attribute case: see <see cref="WolfPkcs11MarksAShortBufferUnavailable"/>.</summary>
    public static bool ShortBufferMarkingAvailable => WolfPkcs11Available && WolfPkcs11MarksAShortBufferUnavailable;

    /// <summary>Gate for cases that verify an RSA signature of the wrong length: see <see cref="WolfPkcs11RejectsWrongLengthRsaSignatures"/>.</summary>
    public static bool WrongLengthRsaSignatureRejectionAvailable => WolfPkcs11Available && WolfPkcs11RejectsWrongLengthRsaSignatures;

    /// <summary>Gate for the over-long raw RSA verify case: see <see cref="WolfPkcs11RefusesOverlongRawRsaDataByItsLength"/>.</summary>
    public static bool OverlongRawRsaVerifyAvailable => WolfPkcs11Available && WolfPkcs11RefusesOverlongRawRsaDataByItsLength;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> with a peer value that is a DER OCTET STRING whose length byte
    /// promises 65 bytes and has 40 answers <c>CKR_FUNCTION_FAILED</c> (<c>src/crypto.c</c> hands the bytes to wolfCrypt,
    /// whose import failure it maps so); a 1 KiB peer value is refused as it should be. PKCS#11 v3.2 §6.3.16 and
    /// §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>.
    /// WolfPkcs11QuirkTests.MalformedEcdhPeer_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11RefusesAMalformedEcdhPeerAsInvalid = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> with SHA-256 and <c>CKA_VALUE_LEN</c> 8161 (255 x 32 + 1, past
    /// RFC 5869's limit) answers <c>CKR_FUNCTION_FAILED</c> (wolfCrypt's refusal, mapped so); 2^32 + 1 and a salt key
    /// that is no secret key are refused as they should be. PKCS#11 v3.2 §6.62.3 (RFC 5869), §4.1 and §5.1.6:
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// WolfPkcs11QuirkTests.HkdfOutputAboveTheRfcLimit_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool WolfPkcs11RefusesAnHkdfOutputAboveTheRfcLimit = false;

    public WolfPkcs11BackendFixture()
    {
        string? libPath = Settings.WolfPkcs11LibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        // Owner-only by construction (CreateTempSubdirectory makes it 0700).
        TokenDirectory = Directory.CreateTempSubdirectory("kl-wolfpkcs11-").FullName;

        // libwolfpkcs11.so reads it through getenv() when it opens its store; as for Kryoptic, .NET's
        // Environment.SetEnvironmentVariable does not reach native getenv() on Linux, so setenv() too.
        SetEnv("WOLFPKCS11_TOKEN_PATH", TokenDirectory);

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            Pkcs11Slot slot = Library.GetSlotList(tokenPresent: false)
                .FirstOrDefault(s => !s.GetTokenInfo().TokenFlags.TokenInitialized)
                ?? throw new InvalidOperationException("wolfPKCS11 listed no slot with an uninitialized token.");

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
            if (TokenDirectory.Length > 0)
                Directory.Delete(TokenDirectory, recursive: true);
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
        string candidate = Path.Join(asmDir, "runtimes", KryopticBackendFixture.GetRid(), "native", "libwolfpkcs11.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the wolfPKCS11 backend.</summary>
[CollectionDefinition("WolfPkcs11")]
public sealed class WolfPkcs11BackendCollection : ICollectionFixture<WolfPkcs11BackendFixture>
{ }
