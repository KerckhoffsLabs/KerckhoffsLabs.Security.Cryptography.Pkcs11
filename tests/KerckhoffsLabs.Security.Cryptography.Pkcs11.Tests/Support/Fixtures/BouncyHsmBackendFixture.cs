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
    /// False while the native client refuses <c>ulSignatureLen == 0</c> in <c>C_Verify</c> with
    /// <c>CKR_ARGUMENTS_BAD</c> (<c>bouncy-pkcs11.c</c>, as does <c>C_VerifyFinal</c>), where an empty signature is simply invalid. Not yet
    /// reported upstream. BouncyHsmQuirkTests.EmptySignature_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptySignature = false;

    /// <summary>
    /// False while <c>C_Logout</c> leaves the application's private session objects in place: a new login finds
    /// them again under their old handles, where PKCS#11 v3.2 §5.6.10 destroys them. While nobody is logged in,
    /// the handle of a private object (session or token) answers <c>C_GetAttributeValue</c> with
    /// <c>CKR_USER_NOT_LOGGED_IN</c>, a code §5.7.5 does not list for it, rather than <c>CKR_OBJECT_HANDLE_INVALID</c>.
    /// Not yet reported upstream. BouncyHsmQuirkTests.PrivateSessionObjectAfterLogout_QuirkStillPresent fails once
    /// it is fixed.
    /// </summary>
    public const bool BouncyHsmDestroysPrivateSessionObjectsOnLogout = false;

    /// <summary>Gate for the C_Logout handle case: see <see cref="BouncyHsmDestroysPrivateSessionObjectsOnLogout"/>.</summary>
    public static bool LogoutInvalidationAvailable => BouncyHsmAvailable && BouncyHsmDestroysPrivateSessionObjectsOnLogout;

    /// <summary>Gate for cases that verify an empty RSA signature: see <see cref="BouncyHsmAcceptsEmptySignature"/>.</summary>
    public static bool WrongLengthRsaSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptySignature;

    /// <summary>
    /// False while a <c>CKM_SP800_108_COUNTER_KDF</c> derive that asks for an additional key
    /// (<c>CK_SP800_108_KDF_PARAMS.pAdditionalDerivedKeys</c>) answers <c>CKR_GENERAL_ERROR</c>. PKCS#11 v3.2 §6.65.6
    /// derives each additional key from the next bytes of the KDF output. Seen on the pinned BouncyHsm.
    /// </summary>
    public const bool BouncyHsmDerivesAdditionalSp800108Keys = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_HKDF_DERIVE)</c> overrides the template's <c>CKA_SENSITIVE</c> and
    /// <c>CKA_EXTRACTABLE</c> from the base key: a sensitive base gives a sensitive key and a non-extractable base a
    /// non-extractable one, whatever the template asks, so an HKDF output cannot be read back. PKCS#11 v3.2 §6.62.3
    /// lets the template set either value; the base key decides only <c>CKA_ALWAYS_SENSITIVE</c> and
    /// <c>CKA_NEVER_EXTRACTABLE</c>. Since harrison314/BouncyHsm 976634e, which fixed harrison314/BouncyHsm#141 in
    /// <c>DeriveKeyGeneratorBase</c>: the §6.43 rule is right for the byte-operation mechanisms, but
    /// <c>HkdfDeriveKeyGenerator</c> shares the base class. Not yet reported upstream.
    /// BouncyHsmQuirkTests.HkdfDerivedKeySensitivity_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmHkdfTakesTheTemplatesSensitivity = false;

    /// <summary>
    /// False while <c>C_DigestFinal</c> with no <c>C_DigestUpdate</c> answers <c>CKR_DATA_LEN_RANGE</c>, where the
    /// digest of an empty message is defined. A single-part <c>C_Digest</c> of empty data works since
    /// harrison314/BouncyHsm 4360a76. BouncyHsmQuirkTests.EmptyMultipartDigest_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmDigestsAnEmptyMultipartMessage = false;

    /// <summary>Gate for the empty multi-part digest case: see <see cref="BouncyHsmDigestsAnEmptyMultipartMessage"/>.</summary>
    public static bool EmptyMultipartDigestAvailable => BouncyHsmAvailable && BouncyHsmDigestsAnEmptyMultipartMessage;

    /// <summary>
    /// False while <c>C_UnwrapKey(CKM_RSA_PKCS_OAEP)</c> of a blob one byte longer than the modulus answers
    /// <c>CKR_WRAPPED_KEY_INVALID</c> (<c>CKR_GENERAL_ERROR</c> before harrison314/BouncyHsm a601b4c). PKCS#11 v3.2
    /// §5.1.6 and §5.18.4: <c>CKR_WRAPPED_KEY_LEN_RANGE</c>.
    /// BouncyHsmQuirkTests.OaepBlobOfTheWrongLength_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnOaepBlobByItsLength = false;

    /// <summary>Gate for the RSA-OAEP wrapped-key length case: see <see cref="BouncyHsmRefusesAnOaepBlobByItsLength"/>.</summary>
    public static bool OaepBlobLengthRefusalAvailable => BouncyHsmAvailable && BouncyHsmRefusesAnOaepBlobByItsLength;

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> changes <c>CKA_MODIFIABLE</c> of an existing object with <c>CKR_OK</c>.
    /// PKCS#11 v3.2 §4.4: it changes only in a copy (§4.1.3). <c>CKA_PRIVATE</c> is refused since harrison314/BouncyHsm
    /// a2cf8fe. BouncyHsmQuirkTests.ModifiableFlagChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesTheModifiableFlag = false;

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> of a new <c>CKA_PUBLIC_EXPONENT</c> on an RSA public key, or
    /// <c>CKA_EC_POINT</c> on an EC public key, answers <c>CKR_OK</c> and the key takes the new value. PKCS#11 v3.2
    /// §6.1.2 and §6.3.3: <c>CKR_ATTRIBUTE_READ_ONLY</c>. An AES <c>CKA_VALUE</c> and an RSA <c>CKA_MODULUS</c> are
    /// refused since harrison314/BouncyHsm a2cf8fe and d530e04.
    /// BouncyHsmQuirkTests.PublicKeyComponentChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesPublicKeyComponents = false;

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> changes an object's <c>CKA_UNIQUE_ID</c> with <c>CKR_OK</c>. PKCS#11
    /// v3.2 §4.4.1: the token generates it and it cannot be changed (<c>CKR_ATTRIBUTE_READ_ONLY</c>). A copy has its
    /// own since harrison314/BouncyHsm 514945b.
    /// BouncyHsmQuirkTests.UniqueIdChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsCkaUniqueIdReadOnly = false;

    /// <summary>Gate for the CKA_UNIQUE_ID case: see <see cref="BouncyHsmKeepsCkaUniqueIdReadOnly"/>.</summary>
    public static bool UniqueIdReadOnlyAvailable => BouncyHsmAvailable && BouncyHsmKeepsCkaUniqueIdReadOnly;

    /// <summary>
    /// False while <c>C_SetPIN</c> takes a PIN shorter than the token's <c>ulMinPinLen</c>: a 3-byte PIN answers
    /// <c>CKR_OK</c> with a reported range of [4, 512]. PKCS#11 v3.2 §5.6.4: <c>CKR_PIN_LEN_RANGE</c>.
    /// <c>C_GetTokenInfo</c> reports the minimum since harrison314/BouncyHsm bf651ed.
    /// BouncyHsmQuirkTests.ShortPin_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmEnforcesItsPinLengthRange = false;

    /// <summary>Gate for the PIN length case: see <see cref="BouncyHsmEnforcesItsPinLengthRange"/>.</summary>
    public static bool PinLengthRangeAvailable => BouncyHsmAvailable && BouncyHsmEnforcesItsPinLengthRange;

    /// <summary>Gate for cases that read back an HKDF-derived key: see <see cref="BouncyHsmHkdfTakesTheTemplatesSensitivity"/>.</summary>
    public static bool HkdfReadbackAvailable => BouncyHsmAvailable && BouncyHsmHkdfTakesTheTemplatesSensitivity;

    /// <summary>Gate for the SP 800-108 additional-key case: see <see cref="BouncyHsmDerivesAdditionalSp800108Keys"/>.</summary>
    public static bool Sp800108AdditionalKeyAvailable => BouncyHsmAvailable && BouncyHsmDerivesAdditionalSp800108Keys;

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
    /// False while <c>C_DeriveKey</c> gives the derived key the template's <c>CKA_SENSITIVE</c> and
    /// <c>CKA_EXTRACTABLE</c>, not the base key's, for <c>CKM_CONCATENATE_BASE_AND_DATA</c>,
    /// <c>CKM_CONCATENATE_DATA_AND_BASE</c>, <c>CKM_XOR_BASE_AND_DATA</c> and <c>CKM_CONCATENATE_BASE_AND_KEY</c>: a
    /// sensitive or unextractable key can be read through a key derived from it. PKCS#11 v3.2 §6.43. Reported upstream
    /// as harrison314/BouncyHsm#141. BouncyHsmQuirkTests.BaseKeyProtection_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsABaseKeysProtection = false;

    /// <summary>Gate for the byte-operation derivations: see <see cref="BouncyHsmKeepsABaseKeysProtection"/>.</summary>
    public static bool BaseKeyProtectionAvailable => BouncyHsmAvailable && BouncyHsmKeepsABaseKeysProtection;

    /// <summary>
    /// False while <c>C_CopyObject</c> changes <c>CKA_ALLOWED_MECHANISMS</c>, wider or narrower, with <c>CKR_OK</c>.
    /// PKCS#11 v3.2 §4.1.3: <c>CKA_ALLOWED_MECHANISMS</c> has no footnote 8, so a copy cannot change it. Not yet reported upstream.
    /// BouncyHsmQuirkTests.AllowedMechanismsCopy_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsAllowedMechanismsOnACopy = false;

    /// <summary>Gate for the copy cases that change <c>CKA_ALLOWED_MECHANISMS</c>: see <see cref="BouncyHsmKeepsAllowedMechanismsOnACopy"/>.</summary>
    public static bool AllowedMechanismsCopyAvailable => BouncyHsmAvailable && BouncyHsmKeepsAllowedMechanismsOnACopy;

    /// <summary>
    /// False while <c>C_CreateObject</c> with <c>CKA_TOKEN</c> given as <c>{NULL, 1}</c> (a NULL <c>pValue</c> with a
    /// length) crashes the process (SIGSEGV): the native client reads the CK_BBOOL without checking the pointer.
    /// PKCS#11 v3.2 §4.1.1 point 2 (<c>CKR_ATTRIBUTE_VALUE_INVALID</c>), or <c>CKR_ARGUMENTS_BAD</c>. Not yet
    /// reported upstream. No tripwire: reproducing the crash would take the test host down.
    /// </summary>
    public const bool BouncyHsmSurvivesANullAttributeValue = false;

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
    /// False while <c>C_EncryptInit</c> / <c>C_DecryptInit</c> with <c>CKM_AES_CTR</c> accept a
    /// <c>CK_AES_CTR_PARAMS.ulCounterBits</c> of 0 or above 128. PKCS#11 v3.2 §6.11.2 takes 1 to 128, and anything
    /// else is <c>CKR_MECHANISM_PARAM_INVALID</c>. Seen since BouncyHsm took <c>CK_AES_CTR_PARAMS</c> (8592a1d1).
    /// BouncyHsmQuirkTests.AesCtrCounterBitsRange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesOutOfRangeAesCtrCounterBits = false;

    /// <summary>
    /// False while a <c>CKM_AES_CTR</c> message longer than the counter's <c>ulCounterBits</c> can count is encrypted
    /// instead of refused: the counter wraps within its width, so a longer message would reuse keystream blocks.
    /// PKCS#11 v3.2 §6.11.2 answers <c>CKR_DATA_LEN_RANGE</c>. Seen since BouncyHsm took <c>CK_AES_CTR_PARAMS</c>
    /// (8592a1d1). BouncyHsmQuirkTests.AesCtrCounterOverflow_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAesCtrCounterOverflow = false;

    /// <summary>
    /// False while a <c>CKM_AES_CBC_PAD</c> <c>C_Decrypt</c> of an empty ciphertext answers <c>CKR_OK</c> with no
    /// plaintext. PKCS#11 v3.2 §5.10.2: a ciphertext of an inappropriate length (CBC-PAD always gives at least one
    /// block) is <c>CKR_ENCRYPTED_DATA_LEN_RANGE</c> or <c>CKR_ENCRYPTED_DATA_INVALID</c>. 15 bytes is refused.
    /// BouncyHsmQuirkTests.EmptyCbcPadCiphertext_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAnEmptyCbcPadCiphertext = false;

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

    /// <summary>
    /// False while a key the HMAC key generators make (<c>CKM_SHA256_KEY_GEN</c>, <c>CKM_SHA3_256_KEY_GEN</c>,
    /// <c>CKM_BLAKE2B_256_KEY_GEN</c>, <c>CKM_SHA512_T_KEY_GEN</c> and the rest) has <c>CKA_KEY_GEN_MECHANISM</c>
    /// <c>CKM_GENERIC_SECRET_KEY_GEN</c>: <c>GenericSecretHmacKeyGenerator</c> builds a <c>GenericSecretKeyObject</c>, whose
    /// constructor fixes that mechanism, and only changes its key type. PKCS#11 v3.2: the attribute names the
    /// mechanism that generated the key. Reported upstream as harrison314/BouncyHsm#146.
    /// BouncyHsmQuirkTests.HmacKeyGenMechanism_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRecordsTheHmacKeyGenMechanism = false;

    /// <summary>
    /// False while <c>CKM_SHAKE_128_KEY_DERIVATION</c> and <c>CKM_SHAKE_256_KEY_DERIVATION</c> derive no more than 32
    /// and 64 bytes and refuse a longer <c>CKA_VALUE_LEN</c> with <c>CKR_TEMPLATE_INCONSISTENT</c>:
    /// <c>DigestDeriveKeyGenerator</c> takes the XOF's default output, <c>GetDigestSize()</c>. A SHAKE is extendable, so
    /// the derived key can be as long as the template asks (PKCS#11 v3.2). Reported upstream as harrison314/BouncyHsm#150.
    /// BouncyHsmQuirkTests.ShakeDerivationLength_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmDerivesShakeKeysOfAnyLength = false;

    /// <summary>The longest key BouncyHsm derives with a SHAKE: see <see cref="BouncyHsmDerivesShakeKeysOfAnyLength"/>.</summary>
    public static string? ShakeDerivationNotTakenBecause(CKM mechanism, int length) =>
        !BouncyHsmDerivesShakeKeysOfAnyLength && length > (mechanism == CKM.CKM_SHAKE_128_KEY_DERIVATION ? 32 : 64)
            ? $"BouncyHsm derives no more than the SHAKE's default output with {mechanism}"
            : null;

    /// <summary>
    /// False while <c>CKM_EXTRACT_KEY_FROM_KEY</c> reads its <c>CK_EXTRACT_PARAMS</c> as a number of bits to keep from
    /// the start of the base key (<c>ExtractKeyFromKeyDeriveKeyGenerator</c>), so bit 0 gives an empty key. PKCS#11 v3.2:
    /// it is the bit the derived key starts at, wrapping around the end of the base key, and
    /// <c>CKA_VALUE_LEN</c> is the derived key's length. Reported upstream as harrison314/BouncyHsm#148.
    /// BouncyHsmQuirkTests.ExtractKeyFromKey_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmExtractsFromTheBitGiven = false;

    /// <summary>Gate for the CKM_EXTRACT_KEY_FROM_KEY cases: see <see cref="BouncyHsmExtractsFromTheBitGiven"/>.</summary>
    public static bool ExtractKeyFromKeyAvailable => BouncyHsmAvailable && BouncyHsmExtractsFromTheBitGiven;

    /// <summary>
    /// False while <c>CKM_AES_CFB1</c> encrypts as CFB with a 128-bit segment: <c>BufferedCipherWrapperFactory</c> maps it
    /// to BouncyCastle's <c>AES/CFB/NOPADDING</c>, whose segment is the block size (the line carries a TODO). PKCS#11 v3.2
    /// and NIST SP 800-38A §6.3: a 1-bit segment. BouncyCastle has no 1-bit CFB (its <c>CfbBlockCipher</c> takes
    /// whole bytes), so the fix is BouncyHsm's. Reported upstream as harrison314/BouncyHsm#149.
    /// BouncyHsmQuirkTests.AesCfb1_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRunsCfb1WithAOneBitSegment = false;

    /// <summary>Gate for the CKM_AES_CFB1 case: see <see cref="BouncyHsmRunsCfb1WithAOneBitSegment"/>.</summary>
    public static bool AesCfb1Available => BouncyHsmAvailable && BouncyHsmRunsCfb1WithAOneBitSegment;

    /// <summary>
    /// False while <c>CKM_SHA512_224_HMAC</c> and <c>CKM_SHA512_256_HMAC</c> take only a <c>CKK_GENERIC_SECRET</c> key and
    /// refuse the <c>CKK_SHA512_224_HMAC</c> and <c>CKK_SHA512_256_HMAC</c> keys their own key generators make, with
    /// <c>CKR_KEY_HANDLE_INVALID</c>: <c>WrapperSignerFactory</c> registers them with no other key type, where the other
    /// HMACs take theirs. PKCS#11 v3.2: these HMACs take a generic secret or their own key type, and a key of
    /// the wrong type is <c>CKR_KEY_TYPE_INCONSISTENT</c>. Reported upstream as harrison314/BouncyHsm#147.
    /// BouncyHsmQuirkTests.Sha512THmacKeyType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmTakesSha512THmacKeys = false;

    /// <summary>Whether the HMAC of a hash family takes the key its key generator makes: see <see cref="BouncyHsmTakesSha512THmacKeys"/>.</summary>
    public static bool HmacTakesItsGeneratedKey(string family) =>
        BouncyHsmTakesSha512THmacKeys || family is not ("SHA-512/224" or "SHA-512/256");

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
