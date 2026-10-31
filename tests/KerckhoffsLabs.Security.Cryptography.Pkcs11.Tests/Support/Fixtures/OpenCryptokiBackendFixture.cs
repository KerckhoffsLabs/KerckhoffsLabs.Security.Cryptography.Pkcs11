using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Backend fixture for a system-installed opencryptoki soft token — a second, independent real
/// PKCS#11 implementation alongside SoftHSM2. Running the same operations against two unrelated
/// modules catches a bug that SoftHSM and the wrapper happen to share (a mis-encoding that survives
/// a SoftHSM-only round-trip).
///
/// opencryptoki is not built from a submodule: it is system-installed and its token is provisioned
/// out-of-band (daemon + <c>pkcsconf</c>, done in CI), so this fixture only opens an already-
/// initialized token. It is inert — every dependent test skips — unless
/// <see cref="Settings.OpenCryptokiLibraryPath"/> points at a loadable library.
/// </summary>
public sealed class OpenCryptokiBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.OpenCryptokiSoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.OpenCryptokiUserPin);
    public string TokenLabel { get; } = Settings.OpenCryptokiTokenLabel;

    /// <summary>Mechanisms the opencryptoki token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the opencryptoki token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when an opencryptoki library has been configured and is loadable.</summary>
    public static bool OpenCryptokiAvailable =>
        Settings.OpenCryptokiLibraryPath is { } p && File.Exists(p);

    // The departures below are opencryptoki's (vendor/opencryptoki at 1cf361530d, the soft token over OpenSSL). The
    // token runs only in CI (it needs pkcsslotd), so each is tied to the source lines that show it and to the return
    // code CI run 41050102152 gave; there is no tripwire.

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_AES_CTR)</c> refuses a counter that is not a whole number of bytes:
    /// <c>ulCounterBits</c> 2 answers <c>CKR_MECHANISM_PARAM_INVALID</c> (<c>usr/lib/common/encr_mgr.c:528-533</c>, and
    /// <c>decr_mgr.c:537-542</c>, refuse <c>ulCounterBits % 8 != 0</c>; <c>mech_aes.c:4219</c> again). PKCS#11 v3.2
    /// §6.11.2 takes any <c>0 &lt; ulCounterBits ≤ 128</c>, and §6.11.3 uses a 2-bit counter as its example.
    /// Confirmed by CI run 41050102152 (<c>CKR_MECHANISM_PARAM_INVALID</c>).
    /// </summary>
    public const bool OpenCryptokiTakesACounterOfAnyWidth = false;

    /// <summary>Gate for the AES-CTR counter overflow case: see <see cref="OpenCryptokiTakesACounterOfAnyWidth"/>.</summary>
    public static bool AesCtrCounterOverflowAvailable => OpenCryptokiAvailable && OpenCryptokiTakesACounterOfAnyWidth;

    /// <summary>
    /// False while a single-part <c>C_Encrypt</c> or <c>C_Decrypt(CKM_AES_CTR)</c> of a length that is not a whole number
    /// of blocks, its length query included, answers <c>CKR_DATA_LEN_RANGE</c> (<c>usr/lib/common/mech_aes.c:427-430</c>
    /// in <c>aes_ctr_encrypt</c>, and the same in <c>aes_ctr_decrypt</c>). PKCS#11 v3.2 §6.11.3 runs counter mode as
    /// SP 800-38A and RFC 3686 define it, a stream cipher whose last block may be partial, and sets no input length.
    /// Confirmed by CI run 41050102152 (<c>CKR_DATA_LEN_RANGE</c> for 56 bytes).
    /// </summary>
    public const bool OpenCryptokiTakesAPartialCtrBlock = false;

    /// <summary>Gate for the AES-CTR length query case: see <see cref="OpenCryptokiTakesAPartialCtrBlock"/>.</summary>
    public static bool AesCtrPartialBlockAvailable => OpenCryptokiAvailable && OpenCryptokiTakesAPartialCtrBlock;

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_AES_GCM)</c> takes a NULL <c>pIv</c> behind <c>ulIvLen</c> 12 or a NULL
    /// <c>pAAD</c> behind a non-zero <c>ulAADLen</c> with <c>CKR_OK</c>: <c>openssl_specific_aes_gcm_init</c>
    /// (<c>usr/lib/common/mech_openssl.c:4818-4836</c>) hands both pointers to OpenSSL unchecked, and
    /// <c>aes_gcm_dup_param</c> (<c>mech_aes.c:3841, 3856</c>) copies each only when it is not NULL. PKCS#11 v3.2
    /// §6.13.2, §6.13.4 and §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> (or <c>CKR_ARGUMENTS_BAD</c>). Confirmed by CI
    /// run 41050102152 (<c>CKR_OK</c> for both).
    /// </summary>
    public const bool OpenCryptokiRefusesANullGcmPointer = false;

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_AES_GCM)</c> answers <c>CKR_FUNCTION_FAILED</c> for a parameter out of range:
    /// <c>ulTagBits</c> 136 is refused as <c>CKR_MECHANISM_PARAM_INVALID</c> (<c>usr/lib/common/mech_openssl.c:4784-4788</c>)
    /// and <c>ulIvLen</c> 0 as <c>CKR_GENERAL_ERROR</c> (OpenSSL's <c>EVP_CTRL_AEAD_SET_IVLEN</c>, <c>mech_openssl.c:4818-4826</c>),
    /// and <c>encr_mgr.c:604-608</c> turns every failure of <c>aes_gcm_init</c> into <c>CKR_FUNCTION_FAILED</c>. PKCS#11
    /// v3.2 §6.13.7 and §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c>. Confirmed by CI run 41050102152
    /// (<c>CKR_FUNCTION_FAILED</c> for both).
    /// </summary>
    public const bool OpenCryptokiRefusesAGcmParameterAsInvalid = false;

    /// <summary>
    /// False while <c>C_EncryptInit(CKM_RSA_PKCS_OAEP)</c> with <c>CKZ_DATA_SPECIFIED</c>, a NULL <c>pSourceData</c> and
    /// <c>ulSourceDataLen</c> 8 answers <c>CKR_OK</c>: <c>encr_mgr.c:315-339</c> checks only the parameter's size, and
    /// <c>rsa_oaep_crypt</c> (<c>usr/lib/common/mech_rsa.c:686, 731-733</c>) refuses source data only with no source and
    /// hashes the empty label when the pointer is NULL. PKCS#11 v3.2 §6.1.7: the length "must be 0" when
    /// <c>pSourceData</c> is NULL; §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> (or <c>CKR_ARGUMENTS_BAD</c>). Confirmed by
    /// CI run 41050102152 (<c>CKR_OK</c>).
    /// </summary>
    public const bool OpenCryptokiRefusesANullOaepLabel = false;

    /// <summary>Gate for the NULL OAEP label case: see <see cref="OpenCryptokiRefusesANullOaepLabel"/>.</summary>
    public static bool NullOaepLabelRefusalAvailable => OpenCryptokiAvailable && OpenCryptokiRefusesANullOaepLabel;

    /// <summary>
    /// False while a key derived with <c>CKM_ECDH1_DERIVE</c> from a generated, sensitive base reads
    /// <c>CKA_ALWAYS_SENSITIVE</c> FALSE: <c>ecdh_pkcs_derive</c> (<c>usr/lib/common/mech_ec.c:1073-1300</c>) never calls
    /// <c>key_mgr_derive_always_sensitive_never_extractable_attrs</c> (<c>key_mgr.c:139</c>, which only the SHA and SSL3
    /// derivations call), so the secret key keeps the FALSE default of <c>secret_key_set_default_attributes</c>
    /// (<c>key.c:1853-1861</c>). PKCS#11 v3.2 §6.3.17: the derived key's <c>CKA_ALWAYS_SENSITIVE</c> follows the base key's
    /// (TRUE when the base key's was and the derived key is <c>CKA_SENSITIVE</c>). Confirmed by CI run 41050102152 (CKA_ALWAYS_SENSITIVE FALSE).
    /// </summary>
    public const bool OpenCryptokiDerivesAnEcdhKeysHistoryFromTheBase = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> refuses a malformed peer value with a code other than
    /// <c>CKR_MECHANISM_PARAM_INVALID</c>: a DER OCTET STRING whose length lies is read as a bare point, which OpenSSL then
    /// rejects (<c>usr/lib/common/mech_ec.c:1655-1735</c>, <c>mech_openssl.c:2010-2014, 2031-2035</c>):
    /// <c>CKR_FUNCTION_FAILED</c>; a 1 KiB value is <c>CKR_PUBLIC_KEY_INVALID</c> (<c>mech_ec.c:1708-1711</c>). And with
    /// <c>CKD_NULL</c>, a <c>CKA_VALUE_LEN</c> of 33 on P-256 is <c>CKR_ARGUMENTS_BAD</c> (<c>mech_ec.c:1061-1068</c>).
    /// PKCS#11 v3.2 §6.3.16 and §5.1.6: <c>CKR_MECHANISM_PARAM_INVALID</c> for the peer; §4.1 and §5.18.5:
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>, <c>CKR_TEMPLATE_INCONSISTENT</c> or <c>CKR_KEY_SIZE_RANGE</c> for the length.
    /// Confirmed by CI run 41050102152 (<c>CKR_FUNCTION_FAILED</c>, <c>CKR_PUBLIC_KEY_INVALID</c>,
    /// <c>CKR_ARGUMENTS_BAD</c>).
    /// </summary>
    public const bool OpenCryptokiRefusesAnEcdhParameterAsInvalid = false;

    /// <summary>
    /// False while <c>C_DeriveKey(CKM_ECDH1_DERIVE)</c> from an AES key answers <c>CKR_TEMPLATE_INCOMPLETE</c>:
    /// <c>ckm_ecdh_pkcs_derive</c> looks up the base key's <c>CKA_ECDSA_PARAMS</c> (<c>usr/lib/common/mech_ec.c:897-903</c>,
    /// <c>template.c:388-391</c>) before it checks the key's class and type (<c>mech_ec.c:908-918</c>). PKCS#11 v3.2
    /// §6.3.17 takes an EC private key; §5.1.6: <c>CKR_KEY_TYPE_INCONSISTENT</c>. Confirmed by CI run 41050102152
    /// (<c>CKR_TEMPLATE_INCOMPLETE</c>).
    /// </summary>
    public const bool OpenCryptokiChecksTheDeriveBaseKeyType = false;

    /// <summary>
    /// False while <c>C_Decrypt(CKM_AES_KEY_WRAP)</c> and <c>CKM_AES_KEY_WRAP_KWP</c> refuse a ciphertext of the wrong
    /// length with other codes: 20 bytes, not a whole number of semiblocks, is <c>CKR_DATA_LEN_RANGE</c> at the length query
    /// (<c>usr/lib/common/mech_aes.c:5076-5080</c>), and 8 bytes passes it, so the call into a buffer reaches OpenSSL, whose
    /// refusal is <c>CKR_GENERAL_ERROR</c> (<c>mech_openssl.c:4401-4406</c>). PKCS#11 v3.2 §5.10.2:
    /// <c>CKR_ENCRYPTED_DATA_LEN_RANGE</c> or <c>CKR_ENCRYPTED_DATA_INVALID</c>. Confirmed by CI run 41050102152
    /// (<c>CKR_DATA_LEN_RANGE</c>, and <c>CKR_GENERAL_ERROR</c> after a length query of <c>CKR_OK</c>).
    /// </summary>
    public const bool OpenCryptokiRefusesAShortKeyWrapCiphertextAsEncryptedDataLenRange = false;

    /// <summary>
    /// False while <c>C_CreateObject</c> of a secret key without <c>CKA_KEY_TYPE</c> answers <c>CKR_TEMPLATE_INCONSISTENT</c>
    /// (<c>usr/lib/common/object.c:111-115</c>: no subclass given). PKCS#11 v3.2 §4.1.1 point 4, §4.8 footnote 1:
    /// <c>CKR_TEMPLATE_INCOMPLETE</c>. Confirmed by CI run 41050102152 (<c>CKR_TEMPLATE_INCONSISTENT</c>). The other
    /// incomplete templates are refused as they should be.
    /// </summary>
    public const bool OpenCryptokiReportsAMissingKeyTypeAsIncomplete = false;

    /// <summary>
    /// False while <c>C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)</c> with <c>CKK_RSA</c> in the private key's template only
    /// answers <c>CKR_TEMPLATE_INCOMPLETE</c>: <c>key_mgr_generate_key_pair</c> compares the private key's type with the
    /// public one's, 0 when the public template gives none (<c>usr/lib/common/key_mgr.c:576-602</c>), and CKK_RSA is 0, so
    /// the contradiction passes; the pair is made, and the private key, still typed CKK_RSA, fails the policy's strength
    /// check for want of <c>CKA_MODULUS</c> (<c>obj_mgr.c:499</c>, <c>usr/lib/api/policy.c:296-301</c>). PKCS#11 v3.2
    /// §5.18.2 and §4.1.1 point 5: <c>CKR_TEMPLATE_INCONSISTENT</c>. Confirmed by CI run 41050102152
    /// (<c>CKR_TEMPLATE_INCOMPLETE</c>). The other inconsistent templates are refused as they should be.
    /// </summary>
    public const bool OpenCryptokiChecksAPrivateKeyTypeOfZero = false;

    /// <summary>
    /// False while <c>C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)</c> with a <c>CKA_PUBLIC_EXPONENT</c> longer than a
    /// <c>CK_ULONG</c> (2^64 + 65537, nine bytes) answers <c>CKR_ATTRIBUTE_VALUE_INVALID</c>
    /// (<c>usr/lib/common/mech_openssl.c:188-191</c>). The value is a valid big integer (§4, Table 12), so §4.1.1 point 2
    /// does not apply, and §6.1.4 names the code for an exponent the implementation cannot use:
    /// <c>CKR_TEMPLATE_INCONSISTENT</c>. Confirmed by CI run 41050102152 (<c>CKR_ATTRIBUTE_VALUE_INVALID</c>).
    /// </summary>
    public const bool OpenCryptokiRefusesALongRsaExponentAsInconsistent = false;

    public OpenCryptokiBackendFixture()
    {
        string? libPath = Settings.OpenCryptokiLibraryPath;
        if (libPath is null || !File.Exists(libPath))
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        Library = Pkcs11Library.Load(libPath);
        try
        {
            Pkcs11Slot found = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException(
                    $"opencryptoki token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens a session, retrying a handful of times when <c>C_Login</c> fails with
    /// <see cref="CKR.CKR_GENERAL_ERROR"/>. Under CI load, opencryptoki's soft-token STDLL
    /// occasionally returns this transiently from its shared-memory session bookkeeping after
    /// hundreds of rapid login/logout cycles in the same run — a token-side flake, not something
    /// a caller did wrong, and PKCS#11 v3.2 §5.1 lists CKR_GENERAL_ERROR as a code a token may
    /// return when "some horrible, unrecoverable error has occurred" without requiring that it be
    /// permanent. SoftHSM and NSS don't exhibit this, so the retry lives here rather than in the
    /// shared <see cref="IPkcs11Backend.OpenSession"/> default.
    /// </summary>
    public Pkcs11Session OpenSession()
    {
        const int maxAttempts = 3;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return Library.OpenSessionWithPin(TokenLabel, CKU.CKU_USER, new SecurePin(UserPin.Span));
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_GENERAL_ERROR && attempt < maxAttempts)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(200 * attempt));
            }
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
    }
}

/// <summary>xUnit collection definition for the opencryptoki backend.</summary>
[CollectionDefinition("OpenCryptoki")]
public sealed class OpenCryptokiBackendCollection : ICollectionFixture<OpenCryptokiBackendFixture> { }
