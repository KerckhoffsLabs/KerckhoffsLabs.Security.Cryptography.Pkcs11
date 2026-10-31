using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture for BouncyHsm (harrison314/BouncyHsm): a PKCS#11 v3.x soft HSM whose
/// native client forwards every call over TCP to a .NET server built on BouncyCastle. It is a sixth,
/// independent implementation alongside the mock, SoftHSM2, NSS, Kryoptic and opencryptoki. Supported on
/// Linux x64 only; elsewhere <see cref="BouncyHsmAvailable"/> is false and its tests skip.
///
/// Built from the vendor/bouncyhsm submodule by the opt-in BuildBouncyHsm MSBuild target
/// (<see cref="Settings.BouncyHsmDirectory"/>). The fixture starts a private, in-memory server
/// (<see cref="BouncyHsmServer"/>), creates one token through its REST API, and points the client at
/// it with <c>BOUNCY_HSM_CFG_STRING</c>, which the client reads when the library loads, so it is set
/// before <see cref="Pkcs11Library.Load(string, Pkcs11LibraryOptions)"/>. Each run starts from a fresh token.
///
/// Known upstream bugs are gated below, one flag each, and
/// <c>Integration/Compat/BouncyHsmQuirkTests</c> fails once a gated bug is fixed.
/// </summary>
public sealed class BouncyHsmBackendFixture : IPkcs11Backend, IDisposable
{
    private readonly BouncyHsmServer? _server;

    public string LibraryPath { get; } = string.Empty;
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = Settings.BouncyHsmTokenLabel;

    /// <summary>Mechanisms the token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True on Linux when a BouncyHsm server and a native client for this RID are staged. Never starts a process.</summary>
    public static bool BouncyHsmAvailable =>
        OperatingSystem.IsLinux() && ServerAssemblyPath() is not null && NativeLibraryPath() is not null;

    /// <summary>
    /// False while the server refuses to digest empty data: the fix for harrison314/BouncyHsm#115 lets
    /// <c>ulDataLen == 0</c> through the client and the server signs and verifies empty data, but
    /// <c>DigestSessionState.Final</c> still answers a digest of no data with <c>CKR_DATA_LEN_RANGE</c>. Not yet
    /// reported upstream. BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptyDigest = false;

    /// <summary>
    /// False while the native client refuses <c>ulSignatureLen == 0</c> in <c>C_Verify</c> with
    /// <c>CKR_ARGUMENTS_BAD</c> (<c>bouncy-pkcs11.c</c>, as does <c>C_VerifyFinal</c>), where an empty signature is simply invalid. Not yet
    /// reported upstream. BouncyHsmQuirkTests.EmptySignature_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptySignature = false;

    /// <summary>
    /// False while <c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c> runs the A chain one PRF ahead: <c>Sp800_108DoublePipelineKdf</c>
    /// computes A(1) = PRF(fixed input) as SP 800-108 §5.3 does, then applies the PRF again before the first block, so
    /// block i is keyed on A(i+1). Feedback mode is not affected. Not yet reported upstream.
    /// BouncyHsmQuirkTests.Sp800108DoublePipeline_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmDoublePipelineMatchesSp800108 = false;

    /// <summary>
    /// False while <c>C_Logout</c> leaves the application's private session objects in place: a new login finds
    /// them again under their old handles, where PKCS#11 v3.2 §5.6.10 destroys them. While nobody is logged in,
    /// the handle of a private object (session or token) answers <c>C_GetAttributeValue</c> with
    /// <c>CKR_USER_NOT_LOGGED_IN</c>, a code §5.7.5 does not list for it, rather than <c>CKR_OBJECT_HANDLE_INVALID</c>.
    /// Not yet reported upstream. BouncyHsmQuirkTests.PrivateSessionObjectAfterLogout_QuirkStillPresent fails once
    /// it is fixed.
    /// </summary>
    public const bool BouncyHsmDestroysPrivateSessionObjectsOnLogout = false;

    /// <summary>
    /// False while the SO and the user can be logged in at once: with the SO logged in, <c>C_Login(CKU_USER)</c>
    /// answers <c>CKR_OK</c> (<c>LoginHandler</c> checks only for a login of the same type), where PKCS#11 v3.2
    /// §5.1.6 answers <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>. Not yet reported upstream.
    /// BouncyHsmQuirkTests.UserLoginOverTheSo_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsTheSoAndTheUserApart = false;

    /// <summary>
    /// False while the SO can make a private object: with the SO logged in, <c>C_CreateObject</c> with
    /// <c>CKA_PRIVATE = TRUE</c> succeeds, where PKCS#11 v3.2 §5.7.1 allows only public objects unless the normal
    /// user is logged in (<c>CKR_USER_NOT_LOGGED_IN</c>, §5.1.6). Not yet reported upstream.
    /// BouncyHsmQuirkTests.PrivateObjectAsTheSo_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesPrivateObjectsToTheSo = false;

    /// <summary>
    /// False while <c>C_GetTokenInfo</c> reports <c>ulMinPinLen</c> as the maximum: the native client copies
    /// <c>MaxPinLen</c> into both fields (<c>bouncy-pkcs11.c</c>, <c>C_GetTokenInfo</c>), so the token reports a
    /// range of [512, 512] that leaves out the PIN it logs in with, where the server's own minimum is 4
    /// (<c>P11Constants.MinPinLength</c>). PKCS#11 v3.2 §3.2 (<c>CK_TOKEN_INFO</c>). Not yet reported upstream.
    /// BouncyHsmQuirkTests.MinimumPinLength_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsItsMinimumPinLength = false;

    /// <summary>
    /// False while <c>C_GetMechanismList</c> into a list too short answers <c>CKR_BUFFER_TOO_SMALL</c> but leaves
    /// <c>*pulCount</c> as the caller gave it: <c>GetMechanismListHandler</c> sends no data with the error, so the
    /// native client has no count to write. PKCS#11 v3.2 §5.5.5: "In either case, the value *pulCount is set to
    /// hold the number of mechanisms". Not yet reported upstream.
    /// BouncyHsmQuirkTests.ShortMechanismList_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsTheMechanismCountOnAShortList = false;

    /// <summary>
    /// False while a sensitive ML-DSA or ML-KEM private key reveals its secret: with <c>CKA_SENSITIVE = TRUE</c>,
    /// <c>C_GetAttributeValue</c> of an ML-DSA key's <c>CKA_VALUE</c> and <c>CKA_SEED</c>, and of an ML-KEM key's
    /// <c>CKA_VALUE</c>, answers <c>CKR_OK</c> and returns the private key. <c>MlDsaPrivateKeyObject</c> and
    /// <c>MlKemPrivateKeyObject</c> (and <c>SlhDsaPrivateKeyObject</c>) do not override
    /// <c>IsSensitiveAttribute</c>, which the RSA, EC, EdDSA and Montgomery private keys do. PKCS#11 v3.2 §6.67.3
    /// and §6.68.3, footnote 7: these attributes cannot be revealed while the key is sensitive (§5.7.5:
    /// <c>CKR_ATTRIBUTE_SENSITIVE</c>, <c>ulValueLen</c> = <c>CK_UNAVAILABLE_INFORMATION</c>). Not yet reported
    /// upstream. BouncyHsmQuirkTests.SensitivePqcPrivateKey_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmHidesSensitivePqcPrivateKeys = false;

    /// <summary>Gate for the short mechanism list case: see <see cref="BouncyHsmReportsTheMechanismCountOnAShortList"/>.</summary>
    public static bool ShortMechanismListAvailable => BouncyHsmAvailable && BouncyHsmReportsTheMechanismCountOnAShortList;

    /// <summary>Gate for the PIN length case: see <see cref="BouncyHsmReportsItsMinimumPinLength"/>.</summary>
    public static bool PinLengthRangeAvailable => BouncyHsmAvailable && BouncyHsmReportsItsMinimumPinLength;

    /// <summary>Gate for the SO-and-user login case: see <see cref="BouncyHsmKeepsTheSoAndTheUserApart"/>.</summary>
    public static bool SoUserExclusionAvailable => BouncyHsmAvailable && BouncyHsmKeepsTheSoAndTheUserApart;

    /// <summary>Gate for the SO private-object case: see <see cref="BouncyHsmRefusesPrivateObjectsToTheSo"/>.</summary>
    public static bool SoPrivateObjectRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesPrivateObjectsToTheSo;

    /// <summary>Gate for the C_Logout handle case: see <see cref="BouncyHsmDestroysPrivateSessionObjectsOnLogout"/>.</summary>
    public static bool LogoutInvalidationAvailable => BouncyHsmAvailable && BouncyHsmDestroysPrivateSessionObjectsOnLogout;

    /// <summary>Gate for empty-input digest cases: see <see cref="BouncyHsmAcceptsEmptyDigest"/>.</summary>
    public static bool EmptyDigestAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptyDigest;

    /// <summary>Gate for cases that verify an empty RSA signature: see <see cref="BouncyHsmAcceptsEmptySignature"/>.</summary>
    public static bool WrongLengthRsaSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptySignature;

    /// <summary>Gate for SP 800-108 double-pipeline cases: see <see cref="BouncyHsmDoublePipelineMatchesSp800108"/>.</summary>
    public static bool Sp800108DoublePipelineAvailable => BouncyHsmAvailable && BouncyHsmDoublePipelineMatchesSp800108;

    /// <summary>
    /// False while a key template without its <c>CKA_MODULUS</c> or <c>CKA_EC_PARAMS</c> is refused with
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>: <c>C_CreateObject</c> of an RSA public or private key without
    /// <c>CKA_MODULUS</c>, or an EC public or private key without <c>CKA_EC_PARAMS</c>. PKCS#11 v3.2 §4.1.1
    /// point 4 has <c>CKR_TEMPLATE_INCOMPLETE</c> for a template missing an attribute the object needs (footnote 1,
    /// §6.1.2, §6.1.3, §6.3.3, §6.3.4). Not yet reported upstream.
    /// BouncyHsmQuirkTests.MissingKeyAttribute_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsAMissingKeyAttributeAsIncomplete = false;

    /// <summary>
    /// False while <c>C_CreateObject</c> of a <c>CKO_SECRET_KEY</c> without <c>CKA_KEY_TYPE</c> makes a key, where
    /// PKCS#11 v3.2 §4.8 (footnote 1) says <c>CKA_KEY_TYPE</c> must be given (§4.1.1 point 4:
    /// <c>CKR_TEMPLATE_INCOMPLETE</c>). Not yet reported upstream.
    /// BouncyHsmQuirkTests.SecretKeyWithoutAKeyType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesASecretKeyWithoutAKeyType = false;

    /// <summary>
    /// False while <c>C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)</c> takes templates whose class or key type the
    /// mechanism does not make: <c>CKK_RSA</c> in the private template, or <c>CKO_PRIVATE_KEY</c> in the public
    /// one, answers <c>CKR_OK</c>, where PKCS#11 v3.2 §5.18.2 answers <c>CKR_TEMPLATE_INCONSISTENT</c>.
    /// <c>C_GenerateKey</c> and <c>C_CreateObject</c> check them. Not yet reported upstream.
    /// BouncyHsmQuirkTests.KeyPairTemplateKeyType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmChecksTheKeyPairTemplatesClassAndKeyType = false;

    /// <summary>
    /// False while <c>C_CopyObject</c> gives the copy the original's <c>CKA_UNIQUE_ID</c>, so two objects in the
    /// session share one. PKCS#11 v3.2 §4.4.1: a value "MUST be generated by the token" for every new object and
    /// be unique across all objects visible to a session. Not yet reported upstream.
    /// BouncyHsmQuirkTests.CopyUniqueId_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmGivesACopyItsOwnUniqueId = false;

    /// <summary>
    /// False while a key's material can be changed after creation: <c>C_SetAttributeValue</c> of a new
    /// <c>CKA_VALUE</c> on an AES key, <c>CKA_MODULUS</c> or <c>CKA_PUBLIC_EXPONENT</c> on an RSA public key and
    /// <c>CKA_EC_POINT</c> on an EC public key, and <c>C_CopyObject</c> with a new <c>CKA_VALUE</c>, answer
    /// <c>CKR_OK</c> and the key takes the new value. PKCS#11 v3.2 §6.7, §6.1.2, §6.3.3 (no footnote 8), §4.1.2
    /// and §4.1.3: <c>CKR_ATTRIBUTE_READ_ONLY</c>. Not yet reported upstream.
    /// BouncyHsmQuirkTests.KeyMaterialChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesKeyMaterial = false;

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> changes <c>CKA_PRIVATE</c> and <c>CKA_MODIFIABLE</c> of an existing
    /// object with <c>CKR_OK</c>. PKCS#11 v3.2 §4.4: "Only the CKA_LABEL attribute can be modified after the
    /// object is created"; these change only in a copy (§4.1.3). <c>CKA_TOKEN</c> is refused
    /// (<c>CKR_GENERAL_ERROR</c>). Not yet reported upstream.
    /// BouncyHsmQuirkTests.PrivateFlagChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesThePrivateAndModifiableFlags = false;

    /// <summary>Gate for the CKA_UNIQUE_ID case: see <see cref="BouncyHsmGivesACopyItsOwnUniqueId"/>.</summary>
    public static bool UniqueIdAvailable => BouncyHsmAvailable && BouncyHsmGivesACopyItsOwnUniqueId;

    /// <summary>Gate for the key material case: see <see cref="BouncyHsmFixesKeyMaterial"/>.</summary>
    public static bool KeyMaterialFixedAvailable => BouncyHsmAvailable && BouncyHsmFixesKeyMaterial;

    /// <summary>
    /// False while <c>C_CreateObject</c> with <c>CKA_TOKEN</c> given as <c>{NULL, 1}</c> (a NULL <c>pValue</c> with a
    /// length) crashes the process (SIGSEGV): the native client reads the CK_BBOOL without checking the pointer.
    /// PKCS#11 v3.2 §4.1.1 point 2 (<c>CKR_ATTRIBUTE_VALUE_INVALID</c>), or <c>CKR_ARGUMENTS_BAD</c>. Not yet
    /// reported upstream. No tripwire: reproducing the crash would take the test host down.
    /// </summary>
    public const bool BouncyHsmSurvivesANullAttributeValue = false;

    /// <summary>
    /// False while a malformed attribute value is refused with <c>CKR_GENERAL_ERROR</c> or
    /// <c>CKR_DEVICE_ERROR</c>: <c>C_CreateObject</c> and <c>C_FindObjectsInit</c> with a 4-byte <c>CKA_TOKEN</c>
    /// answer <c>CKR_GENERAL_ERROR</c>, and with a <c>{NULL, n}</c> <c>CKA_VALUE</c> or <c>CKA_LABEL</c>
    /// <c>CKR_DEVICE_ERROR</c>. PKCS#11 v3.2 §4.1.1 point 2: <c>CKR_ATTRIBUTE_VALUE_INVALID</c> (or
    /// <c>CKR_ARGUMENTS_BAD</c> for the NULL ones). Not yet reported upstream.
    /// BouncyHsmQuirkTests.MalformedAttributeValue_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesMalformedAttributeValues = false;

    /// <summary>Gate for the malformed attribute case: see <see cref="BouncyHsmRefusesMalformedAttributeValues"/>.</summary>
    public static bool MalformedAttributeRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesMalformedAttributeValues;

    /// <summary>
    /// False while <c>C_SetAttributeValue(CKA_COPYABLE = TRUE)</c> on an object created with
    /// <c>CKA_COPYABLE = FALSE</c> answers <c>CKR_OK</c> and makes it copyable again. PKCS#11 v3.2 Table 19:
    /// CKA_COPYABLE "Can't be set to TRUE once it is set to FALSE". Not yet reported upstream.
    /// BouncyHsmQuirkTests.CopyableUndone_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsCkaCopyableFalse = false;

    /// <summary>Gate for the CKA_COPYABLE one-way case: see <see cref="BouncyHsmKeepsCkaCopyableFalse"/>.</summary>
    public static bool CopyableOneWayAvailable => BouncyHsmAvailable && BouncyHsmKeepsCkaCopyableFalse;

    /// <summary>
    /// False while an RSA key of the wrong class is refused with <c>CKR_KEY_HANDLE_INVALID</c>: a public key given
    /// to <c>C_SignRecoverInit</c> and a private key given to <c>C_VerifyRecoverInit</c> (CKM_RSA_PKCS;
    /// <c>RsaWrapperSignWithRecover</c> in BouncyHsm.Core). The handle names a valid key; PKCS#11 v3.2 §5.1.6
    /// keeps <c>CKR_KEY_HANDLE_INVALID</c> for a handle that is not one, and answers a key the mechanism
    /// cannot use with <c>CKR_KEY_TYPE_INCONSISTENT</c> or <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>. Not yet
    /// reported upstream. BouncyHsmQuirkTests.KeyOfTheWrongClass_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsAKeyOfTheWrongClassAsInconsistent = false;

    /// <summary>
    /// False while an object that is not a key, named as one, is refused with <c>CKR_OBJECT_HANDLE_INVALID</c>: a
    /// data object or an X.509 certificate given to <c>C_SignInit</c> or <c>C_EncryptInit</c>, as the wrapping key
    /// of <c>C_WrapKey</c> or the unwrapping key of <c>C_UnwrapKey</c>. The handle is valid; PKCS#11 v3.2 §5.1.6
    /// keeps <c>CKR_OBJECT_HANDLE_INVALID</c> for a handle that is not, lists it for none of these functions, and
    /// answers a non-key with <c>CKR_KEY_HANDLE_INVALID</c> (<c>CKR_WRAPPING_KEY_HANDLE_INVALID</c>,
    /// <c>CKR_UNWRAPPING_KEY_HANDLE_INVALID</c>) or a key-type or key-function code. Not yet reported upstream.
    /// BouncyHsmQuirkTests.NonKeyObjectAsAKey_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesANonKeyObjectAsAKey = false;

    /// <summary>Gate for the non-key object case: see <see cref="BouncyHsmRefusesANonKeyObjectAsAKey"/>.</summary>
    public static bool NonKeyObjectRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesANonKeyObjectAsAKey;

    /// <summary>
    /// False while <c>CKM_AES_CTR</c> takes its parameter as a bare 16-byte counter block rather than a
    /// <c>CK_AES_CTR_PARAMS</c> (<c>ulCounterBits</c> and <c>cb[16]</c>, PKCS#11 v3.2 §6.11.2): the native library
    /// passes it on as raw bytes (<c>bouncy-pkcs11-utils.c</c>), so <c>C_EncryptInit</c> with a real
    /// <c>CK_AES_CTR_PARAMS</c> answers <c>CKR_GENERAL_ERROR</c>. Not yet reported upstream.
    /// BouncyHsmQuirkTests.AesCtrParams_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmTakesAesCtrParams = false;

    /// <summary>Gate for the AES-CTR cases: see <see cref="BouncyHsmTakesAesCtrParams"/>.</summary>
    public static bool AesCtrParamsAvailable => BouncyHsmAvailable && BouncyHsmTakesAesCtrParams;

    /// <summary>
    /// False while a <c>CKM_AES_CBC_PAD</c> <c>C_Decrypt</c> of an empty ciphertext answers <c>CKR_OK</c> with no
    /// plaintext. PKCS#11 v3.2 §5.10.2: a ciphertext of an inappropriate length (CBC-PAD always gives at least one
    /// block) is <c>CKR_ENCRYPTED_DATA_LEN_RANGE</c> or <c>CKR_ENCRYPTED_DATA_INVALID</c>. 15 bytes is refused.
    /// BouncyHsmQuirkTests.EmptyCbcPadCiphertext_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnEmptyCbcPadCiphertext = false;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_RSA_PKCS_OAEP)</c> of a blob one byte short of the modulus answers
    /// <c>CKR_GENERAL_ERROR</c>. PKCS#11 v3.2 §5.1.6 and §5.18.4: <c>CKR_WRAPPED_KEY_LEN_RANGE</c>.
    /// BouncyHsmQuirkTests.OaepBlobOfTheWrongLength_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnOaepBlobByItsLength = false;

    /// <summary>Gate for the RSA-OAEP wrapped-key length case: see <see cref="BouncyHsmRefusesAnOaepBlobByItsLength"/>.</summary>
    public static bool OaepBlobLengthRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesAnOaepBlobByItsLength;

    /// <summary>
    /// False while <c>C_EncryptInit</c> or <c>C_DecryptInit</c> with a <c>CK_GCM_PARAMS</c> or <c>CK_CCM_PARAMS</c>
    /// out of its range (a NULL <c>pIv</c> or <c>pNonce</c>, <c>ulIvLen</c> 0, <c>ulTagBits</c> 136, a nonce of 6 or 14
    /// bytes, <c>ulMACLen</c> 2, 5 or 18) answers <c>CKR_GENERAL_ERROR</c>: <c>BufferedCipherWrapperFactory</c> checks
    /// none of the fields, and BouncyCastle's own refusal is reported as a general error. PKCS#11 v3.2 §6.13.7 and
    /// §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>.
    /// BouncyHsmQuirkTests.OutOfRangeAeadParameter_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnOutOfRangeAeadParameterAsInvalid = false;

    /// <summary>
    /// False while <c>C_EncryptInit</c> or <c>C_DecryptInit</c> with <c>CKM_AES_GCM</c> or <c>CKM_AES_CCM</c> and a NULL
    /// <c>pAAD</c> behind a non-zero <c>ulAADLen</c> answers <c>CKR_OK</c> and runs with no AAD (the ciphertext and tag
    /// are the BCL's with empty AAD). PKCS#11 v3.2 §6.13.2, §6.13.4: <c>pAAD</c> may be NULL only when
    /// <c>ulAADLen</c> is 0; §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> (or <c>CKR_ARGUMENTS_BAD</c>).
    /// BouncyHsmQuirkTests.NullAadPointer_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesANullAadPointer = false;

    /// <summary>
    /// False while a <c>CK_ULONG</c> length in a mechanism parameter is cut to its low 32 bits on a 64-bit platform:
    /// <c>C_SignInit</c> with <c>CKM_SHA256_HMAC_GENERAL</c> and a MAC length of 2^32 + 16 is taken and signs 16
    /// bytes, <c>CKM_AES_CMAC_GENERAL</c> with 2^32 + 8 is taken too, and <c>CKM_SHA256_RSA_PKCS_PSS</c> with an
    /// <c>sLen</c> of 2^32 + 32 signs with a 32-byte salt (a probe's signature verified under a 32-byte salt). PKCS#11 v3.2
    /// §6.22.3, §6.14.3, §6.1.15 and §5.1.6: an out-of-range length is <c>CKR_MECHANISM_PARAM_INVALID</c>; the
    /// in-range rows pass.
    /// BouncyHsmQuirkTests.ParameterLengthAbove32Bits_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAParameterLengthAbove32Bits = false;

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_RSA_PKCS_OAEP)</c> with a NULL <c>pSourceData</c> behind <c>ulSourceDataLen</c>
    /// 8 answers <c>CKR_OK</c> and encrypts with the empty label. PKCS#11 v3.2 §6.1.7: the length "must be 0" when
    /// <c>pSourceData</c> is NULL; §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> (or <c>CKR_ARGUMENTS_BAD</c>).
    /// BouncyHsmQuirkTests.NullOaepLabel_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesANullOaepLabel = false;

    /// <summary>Gate for the NULL OAEP label case: see <see cref="BouncyHsmRefusesANullOaepLabel"/>.</summary>
    public static bool NullOaepLabelRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesANullOaepLabel;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> with <c>CKD_NULL</c> and shared data answers <c>CKR_OK</c> and
    /// derives Z, ignoring the shared data. PKCS#11 v3.2 §6.3.16: with <c>CKD_NULL</c>, "pSharedData must be NULL and
    /// ulSharedDataLen must be zero"; §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>.
    /// BouncyHsmQuirkTests.EcdhSharedDataWithCkdNull_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesSharedDataWithCkdNull = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> on P-256 for a generic secret with <c>CKA_VALUE_LEN</c> 33
    /// answers <c>CKR_OK</c> and makes 00 || Z. PKCS#11 v3.2 §6.3.17: the mechanism only truncates the secret; §4.1
    /// and §5.1.6: <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// BouncyHsmQuirkTests.EcdhValueLenAboveTheSecret_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnEcdhValueLenAboveTheSecret = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> with SHA-256 and <c>CKA_VALUE_LEN</c> 8161 (255 x 32 + 1, past
    /// RFC 5869's limit) answers <c>CKR_GENERAL_ERROR</c>, and with <c>CKA_VALUE_LEN</c> 2^32 + 1 answers <c>CKR_OK</c>
    /// and makes a 1-byte key (the length cut to its low 32 bits). PKCS#11 v3.2 §6.62.3 (RFC 5869), §4.1 and §5.1.6:
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// BouncyHsmQuirkTests.HkdfOutputAboveTheRfcLimit_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnHkdfOutputAboveTheRfcLimit = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> with <c>CKF_HKDF_SALT_KEY</c> and an EC public key as
    /// <c>hSaltKey</c> answers <c>CKR_OBJECT_HANDLE_INVALID</c>; the handle is a valid key's. PKCS#11 v3.2 §6.62.2
    /// names no code: <c>CKR_MECHANISM_PARAM_INVALID</c>, <c>CKR_KEY_HANDLE_INVALID</c> or
    /// <c>CKR_KEY_TYPE_INCONSISTENT</c> (§5.1.6).
    /// BouncyHsmQuirkTests.HkdfSaltKeyOfTheWrongType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsAnHkdfSaltKeyOfTheWrongTypeAsInconsistent = false;

    /// <summary>
    /// Gate for the out-of-range HKDF parameter case: see <see cref="BouncyHsmRefusesAnHkdfOutputAboveTheRfcLimit"/> and
    /// <see cref="BouncyHsmReportsAnHkdfSaltKeyOfTheWrongTypeAsInconsistent"/>.
    /// </summary>
    public static bool HkdfParameterRefusalAvailable =>
        BouncyHsmAvailable && BouncyHsmRefusesAnHkdfOutputAboveTheRfcLimit && BouncyHsmReportsAnHkdfSaltKeyOfTheWrongTypeAsInconsistent;

    /// <summary>
    /// False while a <c>CK_ULONG</c> length attribute in a key template is cut to its low 32 bits on a 64-bit platform:
    /// <c>C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)</c> with <c>CKA_MODULUS_BITS</c> 2^32 + 2048 makes a 2048-bit key
    /// (ulMaxKeySize 6144), and <c>C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN)</c> with <c>CKA_VALUE_LEN</c> 2^32 + 16
    /// answers <c>CKR_OK</c>. PKCS#11 v3.2 §6.1.4, §6.8.3, §4.1 and §5.1.6: <c>CKR_ATTRIBUTE_VALUE_INVALID</c>,
    /// <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// BouncyHsmQuirkTests.KeyLengthAttributeAbove32Bits_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAKeyLengthAttributeAbove32Bits = false;

    /// <summary>
    /// False while <c>C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN)</c> makes a key one byte longer than the ulMaxKeySize it
    /// reports (10485760 bits, so 1310721 bytes). PKCS#11 v3.2 §6.8.3: the range is in bits; past it is
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// </summary>
    public const bool BouncyHsmBoundsAGenericSecretByItsMaximum = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> of a <c>CKK_AES</c> key with <c>CKA_VALUE_LEN</c> 13 answers
    /// <c>CKR_GENERAL_ERROR</c>. PKCS#11 v3.2 §6.10.2 (16, 24 or 32 bytes), §4.1, §5.1.6:
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c>.
    /// BouncyHsmQuirkTests.DerivedAesKeyOfAnInvalidLength_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnAesKeyOfAnInvalidLengthAsInvalid = false;

    /// <summary>Gate for the derived AES key length case: see <see cref="BouncyHsmRefusesAnAesKeyOfAnInvalidLengthAsInvalid"/>.</summary>
    public static bool AesKeyLengthRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesAnAesKeyOfAnInvalidLengthAsInvalid;

    public BouncyHsmBackendFixture()
    {
        if (!BouncyHsmAvailable) return;

        _server = BouncyHsmServer.Start(ServerAssemblyPath()!);
        try
        {
            _server.CreateSlot(TokenLabel, Settings.UserPin, Settings.SoPin);

            string config = $"Server=127.0.0.1; Port={_server.TcpPort}; LogTarget=ErrorConsole; LogLevel=ERROR;";
            Environment.SetEnvironmentVariable("BOUNCY_HSM_CFG_STRING", config);
            SoftHsmBackendFixture.SetNativeEnv("BOUNCY_HSM_CFG_STRING", config);

            LibraryPath = NativeLibraryPath()!;
            Library = Pkcs11Library.Load(LibraryPath);
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"BouncyHsm token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch
        {
            // Library.Dispose logs a failed C_Finalize rather than throwing, so the server is always reached.
            Library?.Dispose();
            _server.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Library?.Dispose();
        _server?.Dispose();
    }

    internal static string? ServerAssemblyPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "server", "BouncyHsm.dll");
        return File.Exists(path) ? path : null;
    }

    internal static string? NativeLibraryPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "runtimes", SoftHsmBackendFixture.GetRid(), "native", "BouncyHsm.Pkcs11Lib.so");
        return File.Exists(path) ? path : null;
    }
}

/// <summary>xUnit collection definition for the BouncyHsm backend.</summary>
[CollectionDefinition("BouncyHsm")]
public sealed class BouncyHsmBackendCollection : ICollectionFixture<BouncyHsmBackendFixture> { }
