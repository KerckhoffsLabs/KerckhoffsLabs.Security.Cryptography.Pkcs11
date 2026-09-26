using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// The default policy: refuses broken or dangerous algorithms, weak key sizes, and plaintext key export.
/// Operation-agnostic by design — the verdict for a mechanism is the same whether it signs or verifies.
/// </summary>
/// <remarks>
/// <para>
/// This is the single, mechanism-level secure-defaults gate; it fires identically for sign,
/// verify, encrypt, decrypt, derive, digest, and key generation (it has no notion of operation
/// direction). Every case dispatches on <c>mechanismType</c> alone except
/// <c>CKM_RSA_PKCS_OAEP</c>, which is one mechanism type for every hash choice — that case
/// additionally inspects <see cref="CkmRsaPkcsOaepParams.HashAlg"/>.
/// </para>
/// <para><b>SHA-224 policy.</b> SHA-224 (<c>CKM_SHA224_RSA_PKCS</c>, <c>_RSA_PKCS_PSS</c>,
/// <c>CKM_ECDSA_SHA224</c>, <c>CKM_SHA224_HMAC</c>, and OAEP's <c>CKM_SHA224</c> hash) is gated
/// the same way as SHA-1, but for a different reason: it isn't cryptographically broken (it's
/// FIPS 180-4-approved, just a truncated SHA-256), but it has no <see cref="HashAlgorithmName"/>
/// constant in the BCL and no practical benefit over SHA-256 on equal-cost hardware, so exposing
/// it by default would be a deviation from the BCL-aligned hash set this API otherwise mirrors.
/// </para>
/// <para><b>RSA PKCS#1 v1.5 policy.</b> The split is deliberate and along two axes —
/// broken hash vs. dangerous padding-use — not "v1.5 vs. PSS":
/// <list type="bullet">
/// <item>Gated: any <em>broken hash</em> in an RSA signature mechanism
/// (<c>CKM_MD2/MD5/SHA1/RIPEMD128/RIPEMD160_RSA_PKCS</c>, <c>CKM_SHA1_RSA_PKCS_PSS</c>).</item>
/// <item>Gated: PKCS#1 v1.5 <em>encryption</em> / raw RSA (<c>CKM_RSA_PKCS</c>, <c>CKM_RSA_X_509</c>)
/// — this is where Bleichenbacher/ROBOT padding-oracle attacks live.</item>
/// <item><b>Allowed:</b> strong-hash (SHA-2/SHA-3) v1.5 <em>signatures</em>
/// (<c>CKM_SHA256_RSA_PKCS</c> etc.). RSASSA-PKCS1-v1_5 with a strong hash is FIPS 186-5-approved
/// and mandated by JWT RS256, TLS 1.2 CertificateVerify, X.509, and code signing. Because this
/// guard is direction-agnostic, gating it would also block <em>verifying</em> third-party
/// signatures — so gating a secure, ubiquitous scheme would both break interop and dilute the
/// meaning of opting out of SecureOnly. PSS is preferred for new code but not required.</item>
/// </list>
/// Mirrored in <c>RSAPkcs11.SignMechanismFor</c> and the README "Security model" section.
/// </para>
/// </remarks>
internal sealed class SecureOnlyPolicy : ICryptoPolicy
{
    public string Name => "SecureOnly";
    public bool AllowsOverride => true;

    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return request switch
        {
            MechanismUseRequest r => EvaluateMechanism(r.Mechanism),
            HashUseRequest r => r.Hash == HashAlgorithmName.SHA1
                ? PolicyDecision.Deny("SHA-1 is collision-broken and deprecated in signature contexts; use SHA-256 or stronger.")
                : PolicyDecision.Allow,
            RsaKeyGenerationRequest r => EvaluateRsaKeyGeneration(r),
            EcKeyGenerationRequest r => r.Curve.IsBelowSecurityBaseline
                ? PolicyDecision.Deny($"EC curve {r.Curve} provides less than 128-bit security; use NistP256 or stronger.")
                : PolicyDecision.Allow,
            // Only CKA_SENSITIVE=false is refused. CKA_EXTRACTABLE=true is not: an extractable key can
            // still be wrapped — exported encrypted under a KEK — which is the standard way to back up
            // and transport keys, and PKCS#11 requires the attribute for it. Demanding an opt-in to use
            // key wrapping at all would misdescribe a safe operation. The value still never leaves in
            // the clear, which is what CKA_SENSITIVE governs and what this refuses.
            //
            // Non-extractable remains the default — Pkcs11Session.BuildSecureKeyDefaults still supplies
            // CKA_EXTRACTABLE=false when the caller says nothing. Asking for extractable is allowed;
            // getting it by omission is not.
            KeyTemplateRequest r => r.Attributes.Any(a => a.Type == (ulong)CKA.CKA_SENSITIVE && !a.GetValueAsBool())
                ? PolicyDecision.Deny("Creating a key with CKA_SENSITIVE=false would create a non-sensitive key whose value can be read off the token.")
                : PolicyDecision.Allow,
            KeyAgreementKdfRequest r => r.Kdf == CKD.CKD_NULL
                ? PolicyDecision.Deny(
                    "CKD_NULL applies no KDF to the ECDH shared secret: the derived AES key becomes the " +
                    "raw x-coordinate (or a token-chosen truncation of it), which NIST SP 800-56A Rev. 3 " +
                    "§5.8 forbids. Use the default CKD_SHA256_KDF unless the token supports only CKD_NULL.")
                : PolicyDecision.Allow,
            KeyMaterialExportRequest r => PolicyDecision.Deny(
                $"Reading the {r.Kind} off the token violates the non-extractable-by-default posture. " +
                "Keep the secret on the token (Pkcs11Key.EncapsulateKey / DecapsulateKey / Derive to a sensitive key)."),
            _ => PolicyDecision.Deny($"SecureOnly has no rule for {request.GetType().Name}."),
        };
    }

    private static PolicyDecision EvaluateRsaKeyGeneration(RsaKeyGenerationRequest r)
    {
        if (r.Mechanism is not (CKM.CKM_RSA_PKCS_KEY_PAIR_GEN or CKM.CKM_RSA_X9_31_KEY_PAIR_GEN))
            return PolicyDecision.Allow;
        return r.ModulusBits < 2048
            ? PolicyDecision.Deny($"RSA-{r.ModulusBits} is below the NIST SP 800-131A 2048-bit minimum; generate a key of at least 2048 bits.")
            : PolicyDecision.Allow;
    }

    // The single mechanism-level secure-defaults gate: given a mechanism, decides whether it is
    // refused outright (broken algorithms, weak modes, dangerous padding) regardless of direction.
    private static PolicyDecision EvaluateMechanism(Mechanism mechanism)
    {
        CKM mechanismType = (CKM)mechanism.Type;

        // Cases are ordered alphabetically by CKM member name (each block's labels are also sorted
        // alphabetically internally), purely to make a given mechanism's gate easy to locate; it
        // carries no semantic meaning.
        switch (mechanismType)
        {
            case CKM.CKM_AES_CBC:
            case CKM.CKM_AES_CBC_PAD:
            case CKM.CKM_AES_CFB1:
            case CKM.CKM_AES_CFB128:
            case CKM.CKM_AES_CFB64:
            case CKM.CKM_AES_CFB8:
            case CKM.CKM_AES_CTR:
            case CKM.CKM_AES_CTS:
            case CKM.CKM_AES_OFB:
                return PolicyDecision.Deny(
                    "Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. Use CKM_AES_GCM or CKM_AES_CCM.");
            case CKM.CKM_AES_ECB:
            case CKM.CKM_ARIA_ECB:
            case CKM.CKM_CAMELLIA_ECB:
                return PolicyDecision.Deny(
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CCM instead.");
            case CKM.CKM_AES_XTS:
                return PolicyDecision.Deny(
                    "AES-XTS provides no integrity protection and is designed for disk-sector encryption, not general-purpose use; use CKM_AES_GCM or CKM_AES_CCM instead.");
            case CKM.CKM_BLOWFISH_CBC:
            case CKM.CKM_BLOWFISH_CBC_PAD:
            case CKM.CKM_BLOWFISH_KEY_GEN:
                return PolicyDecision.Deny(
                    "Blowfish is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            // CKM_CAST5_* are the old names for CKM_CAST128_* (identical enum values), so the
            // CAST128 labels below also match CAST5 calls.
            case CKM.CKM_CAST128_CBC:
            case CKM.CKM_CAST128_CBC_PAD:
            case CKM.CKM_CAST128_ECB:
            case CKM.CKM_CAST128_KEY_GEN:
            case CKM.CKM_CAST128_MAC:
            case CKM.CKM_CAST128_MAC_GENERAL:
            case CKM.CKM_CAST3_CBC:
            case CKM.CKM_CAST3_CBC_PAD:
            case CKM.CKM_CAST3_ECB:
            case CKM.CKM_CAST3_KEY_GEN:
            case CKM.CKM_CAST3_MAC:
            case CKM.CKM_CAST3_MAC_GENERAL:
            case CKM.CKM_CAST_CBC:
            case CKM.CKM_CAST_CBC_PAD:
            case CKM.CKM_CAST_ECB:
            case CKM.CKM_CAST_KEY_GEN:
            case CKM.CKM_CAST_MAC:
            case CKM.CKM_CAST_MAC_GENERAL:
                return PolicyDecision.Deny(
                    "CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            case CKM.CKM_CHACHA20:
            case CKM.CKM_SALSA20:
                return PolicyDecision.Deny(
                    "Raw ChaCha20/Salsa20 provide no integrity protection and are malleable; use CKM_CHACHA20_POLY1305 or CKM_AES_GCM instead.");
            case CKM.CKM_CONCATENATE_BASE_AND_DATA:
            case CKM.CKM_CONCATENATE_BASE_AND_KEY:
            case CKM.CKM_CONCATENATE_DATA_AND_BASE:
            case CKM.CKM_EXTRACT_KEY_FROM_KEY:
            case CKM.CKM_XOR_BASE_AND_DATA:
                return PolicyDecision.Deny(
                    "This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks.");
            case CKM.CKM_DES2_KEY_GEN:
            case CKM.CKM_DES3_KEY_GEN:
            case CKM.CKM_DES_KEY_GEN:
                return PolicyDecision.Deny(
                    "DES and 3DES key generation produces deprecated keys; use CKM_AES_KEY_GEN instead.");
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES_ECB:
                return PolicyDecision.Deny(
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CCM) instead.");
            case CKM.CKM_DES3_CBC_ENCRYPT_DATA:
            case CKM.CKM_DES3_ECB_ENCRYPT_DATA:
                return PolicyDecision.Deny(
                    "DES3 key-derive mechanisms are weak; use CKM_SP800_108-family KDFs or CKM_AES_CBC_ENCRYPT_DATA on a strong base key instead.");
            case CKM.CKM_DES3_MAC:
            case CKM.CKM_DES3_MAC_GENERAL:
            case CKM.CKM_DES_MAC:
            case CKM.CKM_DES_MAC_GENERAL:
                return PolicyDecision.Deny(
                    "DES/3DES MAC is weak; use CKM_AES_CMAC or CKM_SHA256_HMAC instead.");
            case CKM.CKM_DSA:
            case CKM.CKM_DSA_SHA1:
            case CKM.CKM_DSA_SHA224:
            case CKM.CKM_DSA_SHA256:
            case CKM.CKM_DSA_SHA384:
            case CKM.CKM_DSA_SHA512:
                return PolicyDecision.Deny(
                    "DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys; use CKM_ECDSA_SHA256 or CKM_ML_DSA.");
            case CKM.CKM_ECDSA_SHA1:
            case CKM.CKM_SHA_1_HMAC:
            case CKM.CKM_SHA_1_HMAC_GENERAL:
                return PolicyDecision.Deny(
                    "SHA-1 is collision-broken and deprecated in signature/MAC contexts; use CKM_SHA256_HMAC or CKM_ECDSA_SHA256.");
            case CKM.CKM_ECDSA_SHA224:
            case CKM.CKM_SHA224_HMAC:
            case CKM.CKM_SHA224_RSA_PKCS:
            case CKM.CKM_SHA224_RSA_PKCS_PSS:
                return PolicyDecision.Deny(
                    "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over " +
                    "SHA-256 on equal-cost hardware; use CKM_SHA256 or stronger.");
            case CKM.CKM_GOST28147_ECB:
            case CKM.CKM_IDEA_ECB:
                return PolicyDecision.Deny(
                    "This is a legacy 64-bit-block cipher in ECB mode, both leaking structural information from the plaintext and vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM instead.");
            case CKM.CKM_MD2:
            case CKM.CKM_MD2_HMAC:
            case CKM.CKM_MD2_HMAC_GENERAL:
            case CKM.CKM_MD2_KEY_DERIVATION:
            case CKM.CKM_MD2_RSA_PKCS:
                return PolicyDecision.Deny(
                    "MD2 is a broken hash function; use CKM_SHA256 or stronger.");
            case CKM.CKM_MD5:
            case CKM.CKM_SHA_1:
                return PolicyDecision.Deny(
                    "MD5 and SHA-1 are broken hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_MD5_HMAC:
            case CKM.CKM_MD5_HMAC_GENERAL:
            case CKM.CKM_MD5_KEY_DERIVATION:
            case CKM.CKM_SHA1_KEY_DERIVATION:
                return PolicyDecision.Deny(
                    "MD5/SHA-1-based HMAC and key derivation rely on broken hash functions; use CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger instead.");
            case CKM.CKM_MD5_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                return PolicyDecision.Deny(
                    "MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too); use CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 instead.");
            case CKM.CKM_RC2_CBC:
            case CKM.CKM_RC2_CBC_PAD:
            case CKM.CKM_RC2_ECB:
            case CKM.CKM_RC2_KEY_GEN:
            case CKM.CKM_RC2_MAC:
            case CKM.CKM_RC2_MAC_GENERAL:
                return PolicyDecision.Deny(
                    "RC2 is a deprecated 40/64-bit-key cipher with known weaknesses; use CKM_AES_GCM.");
            case CKM.CKM_RC4:
            case CKM.CKM_RC4_KEY_GEN:
                return PolicyDecision.Deny(
                    "RC4 is a broken stream cipher with a biased keystream (prohibited in TLS by RFC 7465); use CKM_AES_GCM.");
            case CKM.CKM_RC5_CBC:
            case CKM.CKM_RC5_CBC_PAD:
            case CKM.CKM_RC5_ECB:
            case CKM.CKM_RC5_KEY_GEN:
            case CKM.CKM_RC5_MAC:
            case CKM.CKM_RC5_MAC_GENERAL:
                return PolicyDecision.Deny(
                    "RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks; use CKM_AES_GCM.");
            case CKM.CKM_RIPEMD128:
            case CKM.CKM_RIPEMD128_HMAC:
            case CKM.CKM_RIPEMD128_HMAC_GENERAL:
            case CKM.CKM_RIPEMD128_RSA_PKCS:
            case CKM.CKM_RIPEMD160:
            case CKM.CKM_RIPEMD160_HMAC:
            case CKM.CKM_RIPEMD160_HMAC_GENERAL:
            case CKM.CKM_RIPEMD160_RSA_PKCS:
                return PolicyDecision.Deny(
                    "RIPEMD-128/160 are deprecated hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_RSA_9796:
                return PolicyDecision.Deny(
                    "ISO 9796-2 RSA signing is forgeable (Coron-Naccache-Stern); use CKM_RSA_PKCS_PSS instead.");
            case CKM.CKM_RSA_PKCS:
                return PolicyDecision.Deny(
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_RSA_PKCS_OAEP:
                // CKM_RSA_PKCS_OAEP is one mechanism type for every hash choice — the hash lives in
                // CkmRsaPkcsOaepParams, not the type, so this is the one case in this switch that
                // inspects parameters rather than dispatching on mechanismType alone.
                if (mechanism.Parameters is CkmRsaPkcsOaepParams { HashAlg: CKM.CKM_SHA_1 })
                    return PolicyDecision.Deny(
                        "SHA-1 is collision-broken; use CKM_SHA256 or stronger as the OAEP hash.");
                if (mechanism.Parameters is CkmRsaPkcsOaepParams { HashAlg: CKM.CKM_SHA224 })
                    return PolicyDecision.Deny(
                        "SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit " +
                        "over SHA-256 on equal-cost hardware; use CKM_SHA256 or stronger as the OAEP hash.");
                return PolicyDecision.Allow;
            case CKM.CKM_RSA_X_509:
                return PolicyDecision.Deny(
                    "Raw RSA (X.509, no padding) is malleable and forgeable; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_SEED_CBC:
            case CKM.CKM_SEED_CBC_ENCRYPT_DATA:
            case CKM.CKM_SEED_CBC_PAD:
            case CKM.CKM_SEED_ECB:
            case CKM.CKM_SEED_ECB_ENCRYPT_DATA:
            case CKM.CKM_SEED_KEY_GEN:
            case CKM.CKM_SEED_MAC:
            case CKM.CKM_SEED_MAC_GENERAL:
                return PolicyDecision.Deny(
                    "SEED is a legacy regional cipher retained only for Korean-standard interop; use CKM_AES_GCM.");
            case CKM.CKM_SKIPJACK_CBC64:
            case CKM.CKM_SKIPJACK_CFB16:
            case CKM.CKM_SKIPJACK_CFB32:
            case CKM.CKM_SKIPJACK_CFB64:
            case CKM.CKM_SKIPJACK_CFB8:
            case CKM.CKM_SKIPJACK_ECB64:
            case CKM.CKM_SKIPJACK_KEY_GEN:
            case CKM.CKM_SKIPJACK_OFB64:
            case CKM.CKM_SKIPJACK_PRIVATE_WRAP:
            case CKM.CKM_SKIPJACK_RELAYX:
            case CKM.CKM_SKIPJACK_WRAP:
                return PolicyDecision.Deny(
                    "SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses; use CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping).");
            case CKM.CKM_SSL3_MD5_MAC:
            case CKM.CKM_SSL3_SHA1_MAC:
                return PolicyDecision.Deny(
                    "SSLv3 MAC mechanisms are tied to a protocol version prohibited by RFC 7568; use TLS 1.2+ with CKM_SHA256_HMAC instead.");
            default:
                return PolicyDecision.Allow;
        }
    }
}
