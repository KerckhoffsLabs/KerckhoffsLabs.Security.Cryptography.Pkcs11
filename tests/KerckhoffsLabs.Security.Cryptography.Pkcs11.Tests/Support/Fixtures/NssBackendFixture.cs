using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Backend fixture over Mozilla NSS softoken (<c>libsoftokn3.so</c>) — a third, fully independent
/// real PKCS#11 implementation alongside SoftHSM2 and opencryptoki. NSS is an unrelated crypto stack
/// (freebl, not OpenSSL), so a bug the wrapper and one backend happen to share is far less likely to
/// survive a round-trip here; it also uniquely exercises ChaCha20-Poly1305 and the SP800-108 counter
/// KDF, which neither CI real backend implements.
///
/// The library is built from the <c>vendor/nss</c> submodule and staged next to the test assembly by
/// the <c>BuildNss</c> MSBuild target; <see cref="Settings.NssLibraryPath"/> overrides the path for
/// one-off local debugging (e.g. pointing at a system <c>libsoftokn3.so</c>).
///
/// The fixture passes <see cref="Settings.NssModuleParameters"/> to <c>C_Initialize</c>: NSS before
/// 3.52 — the v2.40-only releases the <c>pkcs11-v240</c> CI leg runs — refuses to initialize without
/// a parameter string, and later releases accept the same one.
///
/// NSS softoken exposes a "NSS Generic Crypto Services" token whose <c>CKF_LOGIN_REQUIRED</c> flag is
/// clear and that has no user PIN — <c>C_Login</c> on it is rejected with
/// <see cref="CKR.CKR_USER_TYPE_INVALID"/>. The fixture therefore reports
/// <see cref="RequiresUserLogin"/> = <see langword="false"/>, so the shared test cases open it without
/// logging in. The token is write-protected, so only session (public) objects are used — which is all
/// the shared cases need (they create session keys with <c>CKA_TOKEN = false</c>).
/// </summary>
public sealed class NssBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }

    // A login-not-required token has no SO/user PIN; the shared helpers never consult these because
    // RequiresUserLogin is false, but IPkcs11Backend requires them.
    public ReadOnlyMemory<byte> SoPin => ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> UserPin => ReadOnlyMemory<byte>.Empty;

    public string TokenLabel { get; } = Settings.NssTokenLabel;

    /// <summary>NSS softoken's public token needs no login (see the type remarks).</summary>
    public bool RequiresUserLogin => false;

    /// <summary>Mechanisms the NSS token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the NSS token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when an NSS softoken library is configured (or built) and loadable.</summary>
    public static bool NssAvailable =>
        (Settings.NssLibraryPath is { } p && File.Exists(p)) || BuiltLibraryPath() is not null;

    // === NSS generic-token capability gates ================================
    // The login-not-required "NSS Generic Crypto Services" token is write-protected and its classic
    // AES-GCM params path deviates from the other backends. These static gates let the shared-case
    // wrappers skip the affected cases (SkipUnless) instead of failing, the same way the
    // mechanism-list gates skip unsupported mechanisms — so the boundary is visible, not hidden.

    /// <summary>NSS's generic crypto token is write-protected (<c>C_GenerateKey</c>/
    /// <c>C_GenerateKeyPair</c>/<c>C_CreateObject</c> of a token object return
    /// <see cref="CKR.CKR_TOKEN_WRITE_PROTECTED"/>), so shared helpers create session objects instead;
    /// the crypto is exercised identically. Cases that specifically require a persistent token object
    /// skip via <see cref="TokenObjectsAvailable"/>.</summary>
    public bool SupportsTokenObjects => false;

    /// <summary>Gate for cases that specifically need a writable token (persistent keys / token
    /// objects). Always false: NSS's generic token never persists token objects.</summary>
    public static bool TokenObjectsAvailable => false;

    /// <summary>True when the loaded softoken exposes the v3.0 message API (NSS 3.52 and later); false
    /// for the v2.40-only releases, and when NSS is unavailable.</summary>
    public bool SupportsMessageApi { get; }

    /// <summary>The softoken release, which NSS reports as each slot's <c>hardwareVersion</c>
    /// (3.131 for NSS 3.131); <c>0.0</c> when NSS is unavailable.</summary>
    public Version SoftokenVersion { get; } = new(0, 0);

    /// <summary>
    /// Skips the calling test unless the softoken is at least <paramref name="major"/>.<paramref name="minor"/>:
    /// for behaviour a release adds without changing its mechanism list, which the mechanism gates
    /// cannot see.
    /// </summary>
    public void RequireSoftoken(int major, int minor, string reason)
    {
        if (SoftokenVersion < new Version(major, minor))
            Assert.Skip($"NSS {SoftokenVersion} is older than {major}.{minor}: {reason}");
    }

    /// <summary>
    /// Skips the calling test unless AES-GCM can run on this softoken. <c>AesGcmPkcs11</c> uses the
    /// message API where the module has one and otherwise falls back to classic <c>C_EncryptInit</c>
    /// with <c>CK_GCM_PARAMS</c>, which NSS before 3.52 cannot read (see <see cref="RequireClassicAesGcm"/>):
    /// with no message API either, it fails that call with <see cref="CKR.CKR_HOST_MEMORY"/>.
    /// </summary>
    public void RequireAesGcm()
    {
        if (!SupportsMessageApi)
            Assert.Skip("NSS before 3.52 has no message API, and reads CK_GCM_PARAMS without ulIvBits, so AES-GCM does not work on it.");
    }

    /// <summary>
    /// Gate for cases that exercise the classic <c>CK_GCM_PARAMS</c> AES-GCM path. Which softoken releases
    /// accept it is only known once NSS is loaded, so such a case also calls
    /// <see cref="RequireClassicAesGcm"/>.
    /// </summary>
    public static bool ClassicAesGcmAvailable => NssAvailable;

    /// <summary>
    /// Skips the calling test unless AES-GCM works through classic <c>C_EncryptInit</c> +
    /// <c>CK_GCM_PARAMS</c> here: on NSS 3.52 and later, which the library binds through a v3.x interface
    /// and so sends <c>ulIvBits = ulIvLen * 8</c>, as they require. NSS before 3.52 reads a five-field
    /// struct without <c>ulIvBits</c>; the library sends it 0, which it takes as a NULL AAD pointer, and
    /// the call fails.
    /// </summary>
    public void RequireClassicAesGcm()
    {
        if (!Library.LowLevelLibrary!.IsBoundThroughV3Interface)
            Assert.Skip("NSS before 3.52 reads CK_GCM_PARAMS without ulIvBits, so classic AES-GCM does not work on it.");
    }

    /// <summary>True when classic AES-GCM can be fed in pieces through <c>C_EncryptUpdate</c> /
    /// <c>C_DecryptUpdate</c>. Always false, whatever the parameters: softoken's
    /// <c>sftk_CryptInit</c> marks a <see cref="CKM.CKM_AES_GCM"/> context single-part
    /// (<c>context->multi = PR_FALSE</c>), so the update calls fail with
    /// <see cref="CKR.CKR_OPERATION_NOT_INITIALIZED"/>.</summary>
    public static bool SupportsMultipartClassicAesGcm => false;

    /// <summary>Gate for cases that feed classic AES-GCM in pieces.</summary>
    public static bool MultipartClassicAesGcmAvailable => ClassicAesGcmAvailable && SupportsMultipartClassicAesGcm;

    /// <summary>True when the backend will derive a readable (extractable, non-sensitive) key whose
    /// value can be read back. NSS softoken refuses with <see cref="CKR.CKR_KEY_FUNCTION_NOT_PERMITTED"/>
    /// — it only derives non-extractable keys, a deliberate policy against exposing derived key
    /// material. The byte-returning KDF overloads need a readable derived key and so skip here; the
    /// on-token non-extractable derive still runs and exercises the KDF operation on NSS.</summary>
    public static bool SupportsExtractableDerive => false;

    /// <summary>Gate for KDF cases that read the derived key's value back to compare against the BCL.</summary>
    public static bool ExtractableDeriveAvailable => NssAvailable && SupportsExtractableDerive;

    /// <summary>True when <see cref="CKM.CKM_RC2_ECB"/> accepts the spec's <c>CK_RC2_PARAMS</c> (a bare
    /// effective-bits value). NSS softoken routes RC2-ECB and RC2-CBC through one code path that
    /// size-checks both against <c>CK_RC2_CBC_PARAMS</c>, so it rejects the spec-correct ECB params the
    /// wrapper sends with <see cref="CKR.CKR_MECHANISM_PARAM_INVALID"/>. RC2-CBC (which legitimately uses
    /// <c>CK_RC2_CBC_PARAMS</c>) works and is exercised; sending CBC params for ECB would be spec-wrong.</summary>
    public static bool SupportsRc2Ecb => false;

    /// <summary>Gate for the RC2-ECB round-trip case.</summary>
    public static bool Rc2EcbAvailable => NssAvailable && SupportsRc2Ecb;

    /// <summary>True when RSA PKCS#1 v1.5 <em>encryption</em> works through the buffer-growing path.
    /// NSS softoken's <c>RSA_EncryptBlock</c> returns a hard failure (mapped to
    /// <see cref="CKR.CKR_DEVICE_ERROR"/>) when the output buffer is smaller than the modulus, instead
    /// of <see cref="CKR.CKR_BUFFER_TOO_SMALL"/>, so the wrapper's grow-on-buffer-too-small sizing
    /// cannot drive it. RSA-OAEP encryption (length-checked differently by softoken) and every RSA
    /// sign/verify operation work; PKCS#1 v1.5 encryption is insecure (Bleichenbacher) and refused
    /// under Recommended anyway (available only via the AllowInsecure policy).</summary>
    public static bool SupportsRsaPkcs1Encrypt => false;

    /// <summary>Gate for the RSA PKCS#1 v1.5 encryption round-trip case.</summary>
    public static bool RsaPkcs1EncryptAvailable => NssAvailable && SupportsRsaPkcs1Encrypt;

    /// <summary>False while softoken refuses <c>C_VerifyInit</c> for <c>CKM_AES_CMAC</c> with
    /// <see cref="CKR.CKR_MECHANISM_INVALID"/>, although the mechanism advertises <c>CKF_VERIFY</c> and
    /// <c>C_SignInit</c> takes it (https://bugzilla.mozilla.org/show_bug.cgi?id=2075845). Signing works.
    /// NssQuirkTests.CmacVerify_QuirkStillPresent fails once it is fixed.</summary>
    public static bool SupportsCmacVerify => false;

    /// <summary>Gate for the AES-CMAC verify cases.</summary>
    public static bool CmacVerifyAvailable => NssAvailable && SupportsCmacVerify;

    /// <summary>False while softoken sets <c>CKA_LOCAL</c> to <see langword="false"/> on keys it generates with
    /// <c>C_GenerateKey</c> or <c>C_GenerateKeyPair</c>, where PKCS#11 has <see langword="true"/>
    /// (https://bugzilla.mozilla.org/show_bug.cgi?id=2075840). An imported key reports
    /// <see langword="false"/>, as it should. NssQuirkTests.GeneratedKeyLocal_QuirkStillPresent fails once it
    /// is fixed.</summary>
    public static bool SupportsLocalOnGeneratedKeys => false;

    /// <summary>Gate for the cases that check <c>CKA_LOCAL</c> on a generated key.</summary>
    public static bool LocalOnGeneratedKeysAvailable => NssAvailable && SupportsLocalOnGeneratedKeys;

    /// <summary>False while softoken refuses a key whose usage attribute is FALSE (<c>CKA_SIGN</c>, <c>CKA_VERIFY</c>,
    /// <c>CKA_ENCRYPT</c>, <c>CKA_DECRYPT</c>, <c>CKA_VERIFY_RECOVER</c>) with <c>CKR_KEY_TYPE_INCONSISTENT</c>, where
    /// PKCS#11 v3.2 §5.1.6 has <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c> for a key of the right type whose attributes do
    /// not allow the use: <c>sftk_InitGeneric</c> in <c>lib/softoken/pkcs11c.c</c> answers the one code for a key of the
    /// wrong class and for one without the usage. Recorded first for HMAC keys, when KeyCapabilityEnforcementTestCases
    /// accepted any refusal; the AES and RSA rows were confirmed by a run at the pinned 34716626.</summary>
    public static bool SupportsFunctionNotPermittedForKeyUsage => false;

    /// <summary>Gate for the key-usage cases that refuse with <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>: see
    /// <see cref="SupportsFunctionNotPermittedForKeyUsage"/>.</summary>
    public static bool KeyUsageRefusalAvailable => NssAvailable && SupportsFunctionNotPermittedForKeyUsage;

    // === Departures the wolfPKCS11-history cases found ======================
    // Each was confirmed by running the case on a softoken built from vendor/nss at the pinned 34716626, and none is
    // yet reported upstream. NSS needs no tripwire (see NssQuirkTests for the reported ones).

    /// <summary>False while softoken refuses the usage attributes it does check only on some functions:
    /// <c>C_SignRecoverInit</c> with <c>CKA_SIGN_RECOVER</c> FALSE answers <c>CKR_OK</c>. PKCS#11 v3.2 §5.1.6:
    /// <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.</summary>
    public const bool NssChecksCkaSignRecover = false;

    /// <summary>False while <c>C_EncapsulateKey</c> with a public key whose <c>CKA_ENCAPSULATE</c> is FALSE, and
    /// <c>C_DecapsulateKey</c> with a private key whose <c>CKA_DECAPSULATE</c> is FALSE, answer <c>CKR_OK</c>.
    /// PKCS#11 v3.2 §5.1.6: <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.</summary>
    public const bool NssChecksTheKemUsageAttributes = false;

    /// <summary>False while <c>C_DeriveKey</c> (<c>CKM_HKDF_DERIVE</c>, <c>CKM_ECDH1_DERIVE</c>) from a base key whose
    /// <c>CKA_DERIVE</c> is FALSE answers <c>CKR_OK</c>. PKCS#11 v3.2 §5.1.6: <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.</summary>
    public const bool NssChecksCkaDerive = false;

    /// <summary>False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> from an EC private key answers <c>CKR_OK</c>; HKDF
    /// takes a secret key (or a data object, §6.62.3). PKCS#11 v3.2 §5.1.6: <c>CKR_KEY_TYPE_INCONSISTENT</c>.</summary>
    public const bool NssChecksTheHkdfBaseKeyType = false;

    /// <summary>False while <c>C_WrapKey</c> with a data object as the wrapping key, and <c>C_UnwrapKey</c> with a
    /// certificate as the unwrapping key, answer <c>CKR_KEY_TYPE_INCONSISTENT</c> (<c>sftk_InitGeneric</c>). PKCS#11
    /// v3.2 §5.1.6 names the wrapping (unwrapping) key's own codes: <c>CKR_WRAPPING_KEY_HANDLE_INVALID</c> or
    /// <c>CKR_WRAPPING_KEY_TYPE_INCONSISTENT</c> (the unwrapping ones), or <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>.</summary>
    public const bool NssNamesTheWrappingKeyInARefusal = false;

    /// <summary>False while a ciphertext or wrapped key no encryption gives, by its length, is refused with
    /// <c>CKR_DATA_LEN_RANGE</c>: <c>C_Decrypt</c> of an AES-GCM ciphertext shorter than its tag or of an AES key-wrap
    /// (with padding) blob of 8 or 20 bytes, <c>C_UnwrapKey</c> of such a key-wrap blob and of a 255-byte RSA-OAEP
    /// blob under a 2048-bit key. PKCS#11 v3.2 §5.10.2 has <c>C_Decrypt</c> answer <c>CKR_ENCRYPTED_DATA_LEN_RANGE</c>
    /// (or <c>CKR_ENCRYPTED_DATA_INVALID</c>), and §5.18.4 <c>C_UnwrapKey</c> <c>CKR_WRAPPED_KEY_LEN_RANGE</c>;
    /// <c>CKR_DATA_LEN_RANGE</c> is the plaintext's code.</summary>
    public const bool NssRefusesAShortCiphertextAsEncryptedDataLenRange = false;

    /// <summary>False while <c>C_GetAttributeValue</c> of a session object's attribute into a buffer shorter than the
    /// value copies the whole value past the end of the caller's buffer and answers <c>CKR_OK</c>:
    /// <c>NSC_GetAttributeValue</c> in <c>lib/softoken/pkcs11.c</c> <c>memcpy</c>s <c>attrib.ulValueLen</c> bytes
    /// without comparing them with <c>ulValueLen</c>. A heap overflow in the caller. PKCS#11 v3.2 §5.7.5:
    /// <c>CKR_BUFFER_TOO_SMALL</c>, and no value returned.</summary>
    public const bool NssChecksTheAttributeBufferLength = false;

    /// <summary>False while <c>C_Digest(CKM_SHA256)</c> into a 1-byte buffer writes the first byte of the digest,
    /// answers <c>CKR_OK</c> and ends the operation (<c>NSC_Digest</c> passes the length on to the hash's end, which
    /// truncates). PKCS#11 v3.2 §5.2: <c>CKR_BUFFER_TOO_SMALL</c>.</summary>
    public const bool NssRefusesASinglePartDigestIntoAShortBuffer = false;

    /// <summary>False while <c>C_DecryptUpdate(CKM_AES_CBC_PAD)</c> into a 1-byte buffer answers
    /// <c>CKR_BUFFER_TOO_SMALL</c> after moving the input's last block into its padding buffer
    /// (<c>NSC_DecryptUpdate</c>), so the retry with a buffer large enough decrypts the wrong blocks. PKCS#11 v3.2
    /// §5.2: a call refused for a short buffer may be made again, the operation as it was.</summary>
    public const bool NssKeepsADecryptUpdateOnAShortBuffer = false;

    /// <summary>False while <c>C_EncryptInit(CKM_AES_GCM)</c> with <c>ulIvLen</c> 0 or <c>ulTagBits</c> 136 answers
    /// <c>CKR_HOST_MEMORY</c>: freebl's <c>gcm_InitCounter</c> refuses them, and <c>sftk_CryptInit</c> reports any
    /// failed <c>AES_CreateContext</c> as out of memory. PKCS#11 v3.2 §6.13.7, §5.1.6:
    /// <c>CKR_MECHANISM_PARAM_INVALID</c>.</summary>
    public const bool NssRefusesAnOutOfRangeGcmParameterAsInvalid = false;

    /// <summary>False while <c>C_EncryptInit(CKM_AES_CTR)</c> with <c>ulCounterBits</c> 0 or 129 answers
    /// <c>CKR_HOST_MEMORY</c> (the same <c>AES_CreateContext</c> failure). PKCS#11 v3.2 §6.11.2:
    /// <c>CKR_MECHANISM_PARAM_INVALID</c>.</summary>
    public const bool NssRefusesAnOutOfRangeCtrCounterWidthAsInvalid = false;

    /// <summary>False while <c>C_Encrypt(CKM_AES_CTR)</c> under a 2-bit counter starting at 1 refuses three blocks with
    /// <c>CKR_DATA_LEN_RANGE</c>: freebl's <c>CTR_Update</c> (<c>lib/freebl/ctr.c</c>) allows at most 2^counterBits - 2
    /// blocks, wherever the counter starts. PKCS#11 v3.2 §6.11.3 gives this very example: "only 3 blocks of data can
    /// be processed".</summary>
    public const bool NssRunsTheCtrBlocksItsCounterAllows = false;

    /// <summary>False while <c>C_SignInit</c> with <c>CKM_SHA256_HMAC_GENERAL</c> or <c>CKM_AES_CMAC_GENERAL</c> answers
    /// <c>CKR_MECHANISM_PARAM_INVALID</c> for every MAC length, 16 (8) included: <c>sftk_doMACInit</c> hands the
    /// <c>_GENERAL</c> mechanism to <c>sftk_MAC_InitRaw</c> (<c>lib/softoken/sftkhmac.c</c>), which knows only the
    /// full-length ones. Both are advertised with <c>CKF_SIGN</c>. PKCS#11 v3.2 §6.22.3, §6.14.3.</summary>
    public const bool NssRunsTheGeneralLengthMacs = false;

    /// <summary>False while <c>C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN)</c> makes a key of <c>ulMaxKeySize / 8 + 1</c>
    /// bytes: softoken reports <c>ulMaxKeySize</c> 32 and takes 5 bytes. PKCS#11 v3.2 §6.8.3 gives the sizes in bits;
    /// §4.1, §5.1.6: <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.</summary>
    public const bool NssBoundsAGenericSecretByItsMaximum = false;

    /// <summary>False while <c>C_DigestKey</c> of an EC private key answers <c>CKR_KEY_TYPE_INCONSISTENT</c>. PKCS#11
    /// v3.2 §5.12.4 digests "the value of a secret key", and §5.1.6 has a key that cannot be digested answer
    /// <c>CKR_KEY_INDIGESTIBLE</c>.</summary>
    public const bool NssRefusesToDigestAPrivateKeyAsIndigestible = false;

    /// <summary>False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> with a peer value that is no point on the curve answers
    /// <c>CKR_ARGUMENTS_BAD</c> (1 KiB) or <c>CKR_KEY_SIZE_RANGE</c> (a DER OCTET STRING whose length byte promises more
    /// than follows). PKCS#11 v3.2 §6.3.16, §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>.</summary>
    public const bool NssRefusesAMalformedEcdhPeerAsInvalid = false;

    /// <summary>False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> on P-256 for a generic secret with <c>CKA_VALUE_LEN</c>
    /// 33, one byte more than the secret, answers <c>CKR_OK</c>. PKCS#11 v3.2 §6.3.17 (the mechanism only truncates),
    /// §4.1, §5.1.6: <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or
    /// <c>CKR_KEY_SIZE_RANGE</c>.</summary>
    public const bool NssRefusesAnEcdhValueLenAboveTheSecret = false;

    /// <summary>False while <c>C_SignInit(CKM_SHA256_RSA_PKCS_PSS)</c> takes an <c>sLen</c> of 2^32 + 32 and
    /// <c>C_Sign</c> signs (the length is narrowed to 32 bits). PKCS#11 v3.2 §6.1.9, §5.1.6:
    /// <c>CKR_MECHANISM_PARAM_INVALID</c>.</summary>
    public const bool NssRefusesAnOutOfRangePssParameterAsInvalid = false;

    /// <summary>False while <c>C_SetOperationState</c> of a saved SHA-256 digest state cut by its last byte answers
    /// <c>CKR_OK</c>. PKCS#11 v3.2 §5.6.7: <c>CKR_SAVED_STATE_INVALID</c>.</summary>
    public const bool NssChecksTheLengthOfARestoredState = false;

    /// <summary>False while <c>C_SetOperationState</c> of a saved SHA-256 digest state with an encryption or
    /// authentication key handle, which a digest does not use, answers <c>CKR_OK</c>. PKCS#11 v3.2 §5.1.6, §5.6.7:
    /// <c>CKR_KEY_NOT_NEEDED</c>.</summary>
    public const bool NssRefusesAKeyNotNeeded = false;

    /// <summary>False while <c>C_Verify(CKM_RSA_X_509)</c> of <c>m[1..]</c> under a signature over a full 256-byte block
    /// <c>m</c> whose top byte is not zero answers <c>CKR_OK</c>: the data is compared with the recovered block's
    /// trailing bytes only. PKCS#11 v3.2 §6.1.12 converts the data to an integer, so only leading zero bytes may be
    /// left out; §5.15.2: <c>CKR_SIGNATURE_INVALID</c>.</summary>
    public const bool NssVerifiesRawRsaOverTheWholeBlock = false;

    /// <summary>False while <c>C_Verify(CKM_RSA_X_509)</c> of 257 bytes under a 2048-bit key answers
    /// <c>CKR_DEVICE_ERROR</c>. PKCS#11 v3.2 §6.1.12 (Table 45: at most k bytes) and §5.15.2:
    /// <c>CKR_DATA_LEN_RANGE</c>, or <c>CKR_SIGNATURE_INVALID</c>.</summary>
    public const bool NssRefusesOverlongRawRsaVerifyData = false;

    /// <summary>False while a key derived (<c>CKM_HKDF_DERIVE</c>, <c>CKM_ECDH1_DERIVE</c>) sensitive from a base whose
    /// <c>CKA_ALWAYS_SENSITIVE</c> is TRUE reports <c>CKA_ALWAYS_SENSITIVE</c> FALSE. PKCS#11 v3.2 §6.62.3 and §6.3.17:
    /// the derived key's <c>CKA_ALWAYS_SENSITIVE</c> is its <c>CKA_SENSITIVE</c> when the base's is TRUE.</summary>
    public const bool NssDerivesTheSensitivityHistoryFromTheBase = false;

    /// <summary>False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> with <c>CKA_VALUE_LEN</c> 2^32 + 1 answers <c>CKR_OK</c>
    /// (the length is narrowed to 32 bits). RFC 5869 caps the output at 255 hash lengths; PKCS#11 v3.2 §6.62.3, §5.1.6:
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.</summary>
    public const bool NssRefusesAnHkdfValueLenPastTheLimit = false;

    /// <summary>False while <c>C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)</c> with a nine-byte
    /// <c>CKA_PUBLIC_EXPONENT</c> (2^64 + 65537) answers <c>CKR_ARGUMENTS_BAD</c>. PKCS#11 v3.2 §6.1.4: the exponent is
    /// copied from the template, or refused with <c>CKR_TEMPLATE_INCONSISTENT</c>.</summary>
    public const bool NssTakesOrRefusesALongRsaExponent = false;

    /// <summary>False while <c>C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)</c> with <c>CKA_MODULUS_BITS</c> 2^32 + 2048
    /// makes a 2048-bit key (the length is narrowed to 32 bits); softoken reports <c>ulMaxKeySize</c> 2^32 - 1.
    /// PKCS#11 v3.2 §6.1.4, §5.1.6: a modulus above <c>ulMaxKeySize</c> is refused.</summary>
    public const bool NssRefusesAnRsaModulusPastTheMaximum = false;

    /// <summary>Gate for the out-of-range AES-CTR counter width case: see <see cref="NssRefusesAnOutOfRangeCtrCounterWidthAsInvalid"/>.</summary>
    public static bool CtrCounterWidthRefusalAvailable => NssAvailable && NssRefusesAnOutOfRangeCtrCounterWidthAsInvalid;

    /// <summary>Gate for the AES-CTR counter overflow case: see <see cref="NssRunsTheCtrBlocksItsCounterAllows"/>.</summary>
    public static bool CtrBlockCountAvailable => NssAvailable && NssRunsTheCtrBlocksItsCounterAllows;

    /// <summary>Gate for the general-length MAC case: see <see cref="NssRunsTheGeneralLengthMacs"/>.</summary>
    public static bool GeneralLengthMacAvailable => NssAvailable && NssRunsTheGeneralLengthMacs;

    /// <summary>Gate for the short attribute buffer case: see <see cref="NssChecksTheAttributeBufferLength"/>.</summary>
    public static bool AttributeBufferLengthAvailable => NssAvailable && NssChecksTheAttributeBufferLength;

    /// <summary>Gate for the C_SignRecover usage case: see <see cref="NssChecksCkaSignRecover"/>.</summary>
    public static bool SignRecoverUsageRefusalAvailable => NssAvailable && NssChecksCkaSignRecover;

    /// <summary>Gate for the KEM usage cases: see <see cref="NssChecksTheKemUsageAttributes"/>.</summary>
    public static bool KemUsageRefusalAvailable => NssAvailable && NssChecksTheKemUsageAttributes;

    /// <summary>Gate for the CKA_DERIVE usage case: see <see cref="NssChecksCkaDerive"/>.</summary>
    public static bool DeriveUsageRefusalAvailable => NssAvailable && NssChecksCkaDerive;

    /// <summary>Gate for the private-key C_DigestKey case: see <see cref="NssRefusesToDigestAPrivateKeyAsIndigestible"/>.</summary>
    public static bool PrivateKeyDigestRefusalAvailable => NssAvailable && NssRefusesToDigestAPrivateKeyAsIndigestible;

    /// <summary>Gate for the raw RSA leading-bytes case: see <see cref="NssVerifiesRawRsaOverTheWholeBlock"/>.</summary>
    public static bool RawRsaWholeBlockVerifyAvailable => NssAvailable && NssVerifiesRawRsaOverTheWholeBlock;

    /// <summary>Gate for the over-long raw RSA verify case: see <see cref="NssRefusesOverlongRawRsaVerifyData"/>.</summary>
    public static bool OverlongRawRsaVerifyAvailable => NssAvailable && NssRefusesOverlongRawRsaVerifyData;

    /// <summary>Gate for the RSA-OAEP unwrap length case: see <see cref="NssRefusesAShortCiphertextAsEncryptedDataLenRange"/>.</summary>
    public static bool WrappedKeyLenRangeAvailable => NssAvailable && NssRefusesAShortCiphertextAsEncryptedDataLenRange;

    /// <summary>Gate for the derived-key history case: see <see cref="NssDerivesTheSensitivityHistoryFromTheBase"/>.</summary>
    public static bool DerivedKeyHistoryAvailable => NssAvailable && NssDerivesTheSensitivityHistoryFromTheBase;

    /// <summary>
    /// False while <c>C_EncryptInit</c> or <c>C_DecryptInit(CKM_AES_GCM)</c> with a NULL <c>pIv</c> behind a
    /// non-zero <c>ulIvLen</c>, or a NULL <c>pAAD</c> behind a non-zero <c>ulAADLen</c>, ends the test process with
    /// SIGSEGV: <c>sftk_CryptInit</c> in <c>lib/softoken/pkcs11c.c</c> hands both pointers on unchecked, and
    /// freebl's <c>gcm_InitCounter</c> (<c>lib/freebl/gcm.c</c>) copies the IV and hashes the AAD from them.
    /// PKCS#11 v3.2 §6.13.2 lets <c>pAAD</c> be NULL only when <c>ulAADLen</c> is 0, and §5.1.6 has invalid
    /// parameters refused (<c>CKR_MECHANISM_PARAM_INVALID</c>, or <c>CKR_ARGUMENTS_BAD</c>). Confirmed by running
    /// each row alone at the pinned 34716626 (exit code 139). Not yet reported upstream.
    /// </summary>
    public const bool NssSurvivesANullGcmPointer = false;

    public NssBackendFixture()
    {
        string? libPath = Settings.NssLibraryPath ?? BuiltLibraryPath();
        if (libPath is null || !File.Exists(libPath))
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        Library = Pkcs11Library.Load(libPath, new Pkcs11LibraryOptions { ModuleParameters = Settings.NssModuleParameters });
        try
        {
            Pkcs11Slot found = Library.GetSlotList()
                .FirstOrDefault(s => s.GetTokenInfo().Label.TrimEnd() == TokenLabel)
                ?? throw new InvalidOperationException(
                    $"NSS token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
            SupportsMessageApi = Library.LowLevelLibrary!.IsMessageApiSupported;
            SoftokenVersion = found.GetSlotInfo().HardwareVersion;
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
    }

    /// <summary>Path to the softoken staged next to the test assembly by the BuildNss target,
    /// or null when it is absent.</summary>
    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(
            asmDir, "runtimes", SoftHsmBackendFixture.GetRid(), "native", "nss", "libsoftokn3.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the NSS softoken backend.</summary>
[CollectionDefinition("Nss")]
public sealed class NssBackendCollection : ICollectionFixture<NssBackendFixture> { }
