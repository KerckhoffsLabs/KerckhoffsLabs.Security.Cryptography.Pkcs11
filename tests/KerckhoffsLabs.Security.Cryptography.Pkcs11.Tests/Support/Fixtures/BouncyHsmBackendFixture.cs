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
/// (<see cref="BouncyHsmServer"/>), creates its token through its REST API, and points the client at
/// it with <c>BOUNCY_HSM_CFG_STRING</c>, which the client reads when the library loads, so it is set
/// before <see cref="Pkcs11Library.Load(string, Pkcs11LibraryOptions)"/>. Each run starts from a fresh token.
/// A second token, <see cref="QualifiedAreaToken"/>, serves the <c>CKA_ALWAYS_AUTHENTICATE</c> case alone; every
/// other suite uses the first. A failure to set up that second token is kept local
/// (<see cref="QualifiedAreaUnavailableReason"/>): only the case that needs it skips, and the first token's suites run.
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

    // The label the server gives the scratch token; the cases relabel it when they initialize it.
    private const string ScratchTokenLabel = "kl-scratch";

    /// <inheritdoc/>
    public NativeCULong? ScratchSlotId { get; }

    /// <summary>
    /// The second token, on the same server and library: one that simulates a qualified area, where the server marks
    /// a generated private key that is private, sign-only, sensitive and not extractable <c>CKA_ALWAYS_AUTHENTICATE</c>
    /// itself. See <see cref="BouncyHsmTakesAlwaysAuthenticateInATemplate"/>. <see langword="null"/> when
    /// <see cref="BouncyHsmAvailable"/> is false, or when setting it up failed (<see cref="QualifiedAreaUnavailableReason"/>).
    /// </summary>
    public BouncyHsmQualifiedAreaToken? QualifiedAreaToken { get; }

    /// <summary>
    /// Why <see cref="QualifiedAreaToken"/> is <see langword="null"/>, for the skip of the case that needs it;
    /// <see langword="null"/> while the token is set up.
    /// </summary>
    public string? QualifiedAreaUnavailableReason { get; } = "Requires " + nameof(BouncyHsmAvailable);

    /// <summary>Mechanisms the token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True on Linux when a BouncyHsm server and a native client for this RID are staged. Never starts a process.</summary>
    public static bool BouncyHsmAvailable =>
        OperatingSystem.IsLinux() && ServerAssemblyPath() is not null && NativeLibraryPath() is not null;

    /// <summary>
    /// False while <c>C_DigestFinal</c> of a digest that saw no data refuses it with <c>CKR_DATA_LEN_RANGE</c>
    /// (<c>DigestSessionState</c>): a multi-part digest of an empty stream, <c>C_DigestInit</c> then <c>C_DigestFinal</c>
    /// with no <c>C_DigestUpdate</c>, where the digest of nothing is defined like any other. v2.4.0 digests empty
    /// data in a single-part <c>C_Digest</c>; the multi-part path still refuses it. Not yet reported upstream.
    /// BouncyHsmQuirkTests.EmptyDigestStream_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFinishesAnEmptyDigestStream = false;

    /// <summary>Gate for the empty digest stream case: see <see cref="BouncyHsmFinishesAnEmptyDigestStream"/>.</summary>
    public static bool EmptyDigestStreamAvailable => BouncyHsmAvailable && BouncyHsmFinishesAnEmptyDigestStream;

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

    /// <summary>
    /// False while <c>C_SetPIN</c> takes a new PIN outside the token's own PIN length range: with <c>C_GetTokenInfo</c>
    /// reporting [4, 512] (v2.4.0 reports <c>ulMinPinLen</c> correctly), <c>C_SetPIN</c> to a 3-byte PIN answers
    /// <c>CKR_OK</c>. PKCS#11 v3.2 §5.6.7: <c>CKR_PIN_LEN_RANGE</c>. <c>C_Login</c> with such a PIN is refused.
    /// Not yet reported upstream. BouncyHsmQuirkTests.NewPinOutsideTheLengthRange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesANewPinOutsideTheLengthRange = false;

    /// <summary>Gate for the PIN length case: see <see cref="BouncyHsmRefusesANewPinOutsideTheLengthRange"/>.</summary>
    public static bool PinLengthRangeAvailable => BouncyHsmAvailable && BouncyHsmRefusesANewPinOutsideTheLengthRange;

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
    /// False while <c>C_CopyObject</c> takes a <c>CKA_UNIQUE_ID</c> in its template with <c>CKR_OK</c>. PKCS#11 v3.2
    /// §4.4.1: the value is the token's and read-only, so a template that gives it is
    /// <c>CKR_ATTRIBUTE_READ_ONLY</c>, as <c>C_CreateObject</c> and <c>C_SetAttributeValue</c> answer. v2.4.0 gives a
    /// copy its own <c>CKA_UNIQUE_ID</c> (the copy no longer shares the original's). Not yet reported upstream.
    /// BouncyHsmQuirkTests.UniqueIdInACopyTemplate_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRefusesAUniqueIdInACopyTemplate = false;

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> changes the public material of a public key: a new
    /// <c>CKA_PUBLIC_EXPONENT</c> on an RSA public key or <c>CKA_EC_POINT</c> on an EC public key answers
    /// <c>CKR_OK</c>. PKCS#11 v3.2 §6.1.2 and §6.3.3 (no footnote 8), §4.1.2: <c>CKR_ATTRIBUTE_READ_ONLY</c>. v2.4.0
    /// refuses a new <c>CKA_VALUE</c> on an AES key and <c>CKA_MODULUS</c> on an RSA key, and any of them in a copy.
    /// Not yet reported upstream. BouncyHsmQuirkTests.KeyMaterialChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesKeyMaterial = false;

    /// <summary>Whether a key component row runs: see <see cref="BouncyHsmFixesKeyMaterial"/>.</summary>
    public static bool KeyComponentIsFixed(string component) =>
        BouncyHsmFixesKeyMaterial || component is not ("RSA CKA_PUBLIC_EXPONENT" or "EC CKA_EC_POINT");

    /// <summary>
    /// False while <c>C_SetAttributeValue</c> changes <c>CKA_MODIFIABLE</c> of an existing object with <c>CKR_OK</c>.
    /// PKCS#11 v3.2 §4.4: "Only the CKA_LABEL attribute can be modified after the object is created"; it changes only
    /// in a copy (§4.1.3). v2.4.0 refuses a change of <c>CKA_PRIVATE</c>. Not yet reported upstream.
    /// BouncyHsmQuirkTests.ModifiableFlagChange_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmFixesTheModifiableFlag = false;

    /// <summary>Gate for the CKA_UNIQUE_ID case: see <see cref="BouncyHsmRefusesAUniqueIdInACopyTemplate"/>.</summary>
    public static bool UniqueIdAvailable => BouncyHsmAvailable && BouncyHsmRefusesAUniqueIdInACopyTemplate;

    /// <summary>
    /// False while <c>C_DeriveKey</c> gives the derived key the template's <c>CKA_SENSITIVE</c> and
    /// <c>CKA_EXTRACTABLE</c>, not the base key's, for <c>CKM_CONCATENATE_BASE_AND_DATA</c>,
    /// <c>CKM_CONCATENATE_DATA_AND_BASE</c> and <c>CKM_EXTRACT_KEY_FROM_KEY</c>: a sensitive or unextractable key can be
    /// read through a key derived from it. PKCS#11 v3.2 §6.43. Reported upstream as harrison314/BouncyHsm#141; v2.4.0
    /// fixes <c>CKM_CONCATENATE_BASE_AND_KEY</c>, and refuses <c>CKM_XOR_BASE_AND_DATA</c> into a generic secret
    /// (harrison314/BouncyHsm#151), so those rows run or skip on their own.
    /// BouncyHsmQuirkTests.BaseKeyProtection_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsABaseKeysProtection = false;

    /// <summary>Whether a base-key protection row runs: see <see cref="BouncyHsmKeepsABaseKeysProtection"/>.</summary>
    public static bool BaseKeyProtectionIsKept(string derivation) =>
        BouncyHsmKeepsABaseKeysProtection
        || !(derivation.StartsWith("CONCATENATE_BASE_AND_DATA", StringComparison.Ordinal)
            || derivation.StartsWith("CONCATENATE_DATA_AND_BASE", StringComparison.Ordinal)
            || derivation.StartsWith("EXTRACT_KEY_FROM_KEY", StringComparison.Ordinal));

    /// <summary>
    /// False while a key derived from a base that is <c>CKA_NEVER_EXTRACTABLE</c> takes its own <c>CKA_EXTRACTABLE</c>
    /// as its <c>CKA_NEVER_EXTRACTABLE</c>, not the opposite: <c>DeriveKeyGeneratorBase.UpdatePropertiesAfterCeate</c>
    /// sets <c>CkaNewerExtractable = CkaExtractable</c>. A <c>CKM_HKDF_DERIVE</c> key made unextractable from a generated,
    /// unextractable base reports <c>CKA_NEVER_EXTRACTABLE = FALSE</c> (and an extractable one would report TRUE).
    /// PKCS#11 v3.2 §6.62.3 (and §4.10 for the attribute): it is TRUE if the base's is TRUE and the derived key's
    /// <c>CKA_EXTRACTABLE</c> is FALSE. New in v2.4.0, with the derivation refactor for harrison314/BouncyHsm#141
    /// (<c>CKM_ECDH1_DERIVE</c>, on another path, is right). Not yet reported upstream.
    /// BouncyHsmQuirkTests.DerivedNeverExtractable_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmSetsADerivedKeysNeverExtractable = false;

    /// <summary>Whether a derived-key provenance row runs: see <see cref="BouncyHsmSetsADerivedKeysNeverExtractable"/>.</summary>
    public static bool DerivedKeyProvenanceIsRight(string derivation) =>
        BouncyHsmSetsADerivedKeysNeverExtractable || derivation != "HKDF";

    /// <summary>
    /// False while a key template cannot set <c>CKA_ALWAYS_AUTHENTICATE</c>: the server lists it among the read-only
    /// attributes (<c>StorageObject.IsReadOnlyAttribute</c>, <c>src/Src/BouncyHsm.Core/Services/Contracts/Entities/StorageObject.cs</c>),
    /// so <c>C_GenerateKeyPair</c>, <c>C_CreateObject</c> and <c>C_SetAttributeValue</c> with it answer
    /// <c>CKR_ATTRIBUTE_READ_ONLY</c>. PKCS#11 v3.2 §4.10 (private key objects) gives it no footnote, so a template
    /// may set it. The server sets it itself only on a token made with <c>SimulateQualifiedArea</c>, for a generated
    /// private key that is private, sign-only, sensitive and not extractable (<c>PrivateKeyHelper.ComputeCkaAlwaysAuthenticate</c>,
    /// <c>GenerateKeyPairHandler.UpdatePrivateKey</c>). The shared test token is made without it, as that would mark
    /// every sign-only key of every suite; the always-authenticate case runs instead on <see cref="QualifiedAreaToken"/>,
    /// a second token made with it, where the key's template leaves the attribute to the server, and its context
    /// login (<c>LoginHandler</c>) takes that token's signature PIN. Reported upstream as
    /// <see href="https://github.com/harrison314/BouncyHsm/issues/145"/>.
    /// <para>
    /// No test is gated on this flag: the case runs ungated on <see cref="QualifiedAreaToken"/>. It is kept as the
    /// record of the quirk for the #145 canary, BouncyHsmQuirkTests.AlwaysAuthenticateInATemplate_QuirkStillPresent,
    /// which fails once it is fixed: then delete the canary and this flag, and the case may move back to the shared
    /// token.
    /// </para>
    /// </summary>
    public const bool BouncyHsmTakesAlwaysAuthenticateInATemplate = false;

    /// <summary>
    /// False while <c>C_CopyObject</c> changes <c>CKA_ALLOWED_MECHANISMS</c>, wider or narrower, with <c>CKR_OK</c>.
    /// PKCS#11 v3.2 §4.1.3: <c>CKA_ALLOWED_MECHANISMS</c> has no footnote 8, so a copy cannot change it. Not yet reported upstream.
    /// BouncyHsmQuirkTests.AllowedMechanismsCopy_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsAllowedMechanismsOnACopy = false;

    /// <summary>Gate for the copy cases that change <c>CKA_ALLOWED_MECHANISMS</c>: see <see cref="BouncyHsmKeepsAllowedMechanismsOnACopy"/>.</summary>
    public static bool AllowedMechanismsCopyAvailable => BouncyHsmAvailable && BouncyHsmKeepsAllowedMechanismsOnACopy;

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
    /// False while <c>C_DeriveKey(CKM_CONCATENATE_BASE_AND_KEY)</c> ignores the second key's <c>CKA_ALLOWED_MECHANISMS</c>:
    /// a second key whose list leaves the mechanism out is concatenated anyway, and only the base key's list is
    /// checked. PKCS#11 v3.2 §4.8 Table 26: the list names the mechanisms "allowed to be used with this key", which we
    /// read as covering both keys of the derivation (BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced).
    /// Not yet reported upstream. BouncyHsmQuirkTests.SecondKeysAllowedMechanisms_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmChecksTheSecondKeysAllowedMechanisms = false;

    /// <summary>
    /// False while a one-byte key made from a sensitive, unextractable key can be digested:
    /// <c>CKM_EXTRACT_KEY_FROM_KEY</c> and <c>CKM_XOR_BASE_AND_DATA</c> with <c>CKA_VALUE_LEN</c> 1 make a sensitive
    /// key, as §6.43 requires, but <c>C_DigestKey</c> takes it, and its SHA-256 gives the byte away among 256
    /// candidates: a byte of the protected key per call. Refusing the one-byte derivation from a protected key, or
    /// the digest of a key made from one, would close it. After pkcs11-check's 1-byte recovery oracle
    /// (https://github.com/mingulov/pkcs11-check, test_misc_kdf.py, 0.3.1). Not yet reported upstream. BouncyHsmQuirkTests.OneByteKeyDigest_QuirkStillPresent
    /// fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmKeepsAProtectedKeysBytesFromADigest = false;

    /// <summary>
    /// False while a key of the wrong type is refused with <c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>, even when it has the
    /// usage the operation needs: BouncyHsm gives every key a default <c>CKA_ALLOWED_MECHANISMS</c> of its own type's
    /// mechanisms (<c>KeyObject.GetAllovedMechanism</c>), and <c>CheckAllowedMechanism</c> runs before the key's type is
    /// looked at, in C_SignInit, C_VerifyInit, C_EncryptInit and C_DeriveKey. The key is refused, as it must be, with
    /// another code: PKCS#11 v3.2 §5.1.6 answers a key of the wrong type with <c>CKR_KEY_TYPE_INCONSISTENT</c>, and an
    /// absent <c>CKA_ALLOWED_MECHANISMS</c> restricts nothing (§4.8 Table 26). Not yet reported upstream.
    /// BouncyHsmQuirkTests.KeyOfTheWrongType_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmReportsAKeyOfTheWrongTypeAsInconsistent = false;

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
    /// False while <c>C_UnwrapKey(CKM_RSA_PKCS_OAEP)</c> of a blob one byte longer than the modulus answers
    /// <c>CKR_WRAPPED_KEY_INVALID</c>. PKCS#11 v3.2 §5.1.6 and §5.18.4: <c>CKR_WRAPPED_KEY_LEN_RANGE</c>. v2.4.0
    /// answers a blob one byte short with it; before, both answered <c>CKR_GENERAL_ERROR</c>.
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
    /// in-range rows pass. v2.4.0 keeps 64-bit attribute values whole (harrison314/BouncyHsm#136), but not these.
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
            // The second token's failure stays its own: see QualifiedAreaUnavailableReason.
            bool qualifiedCreated = TrySetUp(() =>
                {
                    _server.CreateSlot(Settings.BouncyHsmQualifiedTokenLabel, Settings.BouncyHsmQualifiedUserPin,
                        Settings.BouncyHsmQualifiedSoPin, Settings.BouncyHsmQualifiedSignaturePin);
                    return true;
                }, out string? qualifiedFailure);
            // The scratch token TokenAdministrationTestCases initialize afresh with C_InitToken, which takes the SO PIN
            // the server gave it. Its failure stays its own: those cases skip.
            bool scratchCreated = TrySetUp(() =>
                {
                    _server.CreateSlot(ScratchTokenLabel, Settings.UserPin, Settings.ScratchSoPin);
                    return true;
                }, out string? scratchFailure);
            if (!scratchCreated)
                Console.Error.WriteLine($"BouncyHsm's scratch token could not be set up: {scratchFailure}");

            string config = $"Server=127.0.0.1; Port={_server.TcpPort}; LogTarget=ErrorConsole; LogLevel=ERROR;";
            Environment.SetEnvironmentVariable("BOUNCY_HSM_CFG_STRING", config);
            SoftHsmBackendFixture.SetNativeEnv("BOUNCY_HSM_CFG_STRING", config);

            LibraryPath = NativeLibraryPath()!;
            Library = Pkcs11Library.Load(LibraryPath);
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"BouncyHsm token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
            if (scratchCreated)
            {
                ScratchSlotId = Library.GetSlotList().Where(s => s.GetTokenInfo().Label == ScratchTokenLabel)
                    .Select(s => (NativeCULong?)(NativeCULong)s.SlotId.Value).FirstOrDefault();
            }

            Pkcs11Library library = Library;
            string libraryPath = LibraryPath;
            QualifiedAreaToken = qualifiedCreated
                ? TrySetUp(() =>
                {
                    Pkcs11Slot qualified = library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == Settings.BouncyHsmQualifiedTokenLabel)
                        ?? throw new InvalidOperationException($"BouncyHsm token '{Settings.BouncyHsmQualifiedTokenLabel}' did not appear in the slot list.");
                    return new BouncyHsmQualifiedAreaToken(libraryPath, library, (NativeCULong)qualified.SlotId.Value,
                        new HashSet<CKM>(qualified.GetMechanismList()));
                }, out qualifiedFailure)
                : null;
            QualifiedAreaUnavailableReason = QualifiedAreaToken is null
                ? $"BouncyHsm's qualified-area token could not be set up: {qualifiedFailure}"
                : null;
            if (QualifiedAreaUnavailableReason is not null)
                Console.Error.WriteLine(QualifiedAreaUnavailableReason);
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

    /// <summary>
    /// Runs <paramref name="setUp"/> for a part of the fixture whose failure must stay local (the qualified-area
    /// token): its result, or <see langword="null"/> with <paramref name="failure"/> saying why. Only for such a part:
    /// the first token's set-up still throws, and fails the fixture.
    /// </summary>
    internal static T? TrySetUp<T>(Func<T> setUp, out string? failure) where T : notnull
    {
        try
        {
            failure = null;
            return setUp();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            failure = $"{ex.GetType().Name}: {ex.Message}";
            return default;
        }
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

/// <summary>
/// The BouncyHsm fixture's second token, made with <c>SimulateQualifiedArea</c> (<see cref="BouncyHsmServer.CreateSlot"/>),
/// as a backend of its own over the fixture's server and library, which it neither owns nor disposes. It serves the
/// <c>CKA_ALWAYS_AUTHENTICATE</c> case alone (see <see cref="BouncyHsmBackendFixture.BouncyHsmTakesAlwaysAuthenticateInATemplate"/>):
/// the server marks every private, sign-only, sensitive and not extractable key it generates there, and reports
/// <c>CKF_SECONDARY_AUTHENTICATION</c>.
/// </summary>
public sealed class BouncyHsmQualifiedAreaToken(string libraryPath, Pkcs11Library library, NativeCULong slotId,
    IReadOnlySet<CKM> supportedMechanisms) : IPkcs11Backend
{
    public string LibraryPath { get; } = libraryPath;
    public Pkcs11Library Library { get; } = library;
    public NativeCULong SlotId { get; } = slotId;
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.BouncyHsmQualifiedSoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.BouncyHsmQualifiedUserPin);

    /// <summary>The PIN the token's <c>C_Login(CKU_CONTEXT_SPECIFIC)</c> takes, distinct from <see cref="UserPin"/>.</summary>
    public ReadOnlyMemory<byte> SignaturePin { get; } = Encoding.UTF8.GetBytes(Settings.BouncyHsmQualifiedSignaturePin);

    public string TokenLabel { get; } = Settings.BouncyHsmQualifiedTokenLabel;
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = supportedMechanisms;
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);
}

/// <summary>xUnit collection definition for the BouncyHsm backend.</summary>
[CollectionDefinition("BouncyHsm")]
public sealed class BouncyHsmBackendCollection : ICollectionFixture<BouncyHsmBackendFixture> { }
