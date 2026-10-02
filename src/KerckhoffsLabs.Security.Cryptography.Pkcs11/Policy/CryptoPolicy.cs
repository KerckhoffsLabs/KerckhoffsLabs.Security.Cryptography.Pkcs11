using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>The built-in <see cref="ICryptoPolicy"/> instances.</summary>
public static class CryptoPolicy
{
    /// <summary>
    /// The default policy: an allow-list of reviewed, modern mechanisms (AES-GCM/CCM, AES key wrap,
    /// ChaCha20-Poly1305, SHA-2/SHA-3 digests and HMAC, RSA-PSS/OAEP and SHA-2 PKCS#1 v1.5 signatures,
    /// ECDSA, EdDSA, ECDH, ML-KEM, ML-DSA, SLH-DSA, SP 800-108, HKDF, PBKDF2), each for the operations it is
    /// meant for, plus allow-lists of hashes, EC curves (128-bit security or more) and key-agreement KDFs.
    /// <b>Denies by default:</b> everything else — including unreviewed standard mechanisms and every
    /// vendor-defined mechanism — is refused, whether or not it also appears in the documented (but
    /// non-enforcing) deny list. Also refuses AES-GCM tags under 96 bits and AES-CCM MACs under 64 bits (in
    /// the single-part and message-based parameters alike), RSA keys under 2048 bits, non-sensitive key
    /// templates, and reading secret key material off the token.
    /// </summary>
    /// <remarks>
    /// The full generated catalogue — every allowed mechanism/hash/curve/KDF/PRF with its rationale, the
    /// documented deny list — is at <c>docs/policies/recommended.md</c> in the repository. To allow a reviewed
    /// mechanism, derive your own policy: <c>CryptoPolicy.Recommended.ToBuilder("MyApp").AllowMechanism(...).Build()</c>.
    /// </remarks>
    public static ComposedCryptoPolicy Recommended { get; } = RecommendedDefinition.Create();

    /// <summary>
    /// Allows only NIST-approved security functions (SP 800-131A / SP 800-140C, FIPS 186-5, FIPS 203–205),
    /// with SP 800-131A "legacy use" permitted for TDEA decryption/unwrapping, TDEA CMAC verification, and
    /// SHA-1/DSA signature verification. RSA PKCS#1 v1.5 encryption and decryption/unwrap are refused. AES
    /// key wrapping is approved only via KW/KWP (<c>CKM_AES_KEY_WRAP</c>, <c>CKM_AES_KEY_WRAP_KWP</c>) or the
    /// GCM/CCM modes; <c>CKM_AES_KEY_WRAP_PAD</c>, whose padding is vendor-defined, is refused. Other AES
    /// modes encrypt and decrypt data but may not wrap or unwrap keys. AES-GCM tags must be 96 to 128 bits
    /// (SP 800-38D §5.2.1.2: shorter tags need application conditions a policy cannot verify) and AES-CCM
    /// MACs at least 64 bits (SP 800-38C Appendix B.2). <b>Denies by default:</b> refuses every mechanism, hash, curve, KDF and PRF
    /// not on its allow-list, including every vendor-defined mechanism, whether or not it also appears in
    /// the documented (but non-enforcing) deny list. A workspace opened under this policy refuses every
    /// <c>UsePolicy</c> override.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This restricts what the library sends to the token. It does <b>not</b> make an application FIPS 140-3
    /// compliant — that also requires a validated cryptographic module operating in its approved mode.
    /// </para>
    /// <para>
    /// The full generated catalogue — every allowed mechanism/hash/curve/KDF/PRF with its NIST citation and
    /// the documented deny list — is at <c>docs/policies/nist-approved.md</c> in the repository.
    /// </para>
    /// <para>Known limits — the policy judges requests, not the token's contents:</para>
    /// <list type="bullet">
    /// <item><description>It judges mechanisms, parameters and <i>requested</i> key sizes and curves. It does
    /// not inspect the size or curve of keys already on the token: using an existing RSA-1024 or Brainpool key
    /// is not refused. (For ECDH the existing key's type is checked, so an X25519/X448 key is refused.)</description></item>
    /// <item><description>Raw <c>CKM_RSA_PKCS</c> signing and raw <c>CKM_ECDSA</c> cannot see which digest the
    /// caller pre-computed, so the digest is not checked.</description></item>
    /// </list>
    /// <para>
    /// A policy derived with <see cref="ComposedCryptoPolicy.ToBuilder(string)"/> gets its own name and keeps
    /// <see cref="ICryptoPolicy.AllowsOverride"/> false unless changed; <c>CryptoPolicy.NistApproved</c> itself never changes.
    /// </para>
    /// </remarks>
    public static ComposedCryptoPolicy NistApproved { get; } = NistApprovedDefinition.Create();

    /// <summary>
    /// Allows everything, including broken algorithms and plaintext key export. For legacy interop only.
    /// </summary>
    /// <remarks>
    /// Reach for the narrowest opt-in first. Most single needs have one on the builder that
    /// <c>Recommended.ToBuilder(name)</c> returns, and every other Recommended rule keeps applying:
    /// <list type="bullet">
    /// <item><description>a legacy mechanism — <see cref="CryptoPolicyBuilder.AllowMechanism(Common.CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>;</description></item>
    /// <item><description>reading one kind of secret off the token (the <c>…AndExportSecret</c> operations on
    /// <see cref="Pkcs11Key"/> and <see cref="Pkcs11Workspace"/>, and the byte-returning ECDH, ML-KEM and
    /// KDF adapters built on them) — <see cref="CryptoPolicyBuilder.AllowSecretExport"/>;</description></item>
    /// <item><description>a weak EC curve — <see cref="CryptoPolicyBuilder.AllowCurve(Pkcs11ECCurve, string)"/>;</description></item>
    /// <item><description>a key-agreement KDF — <see cref="CryptoPolicyBuilder.AllowKeyAgreementKdf"/>.</description></item>
    /// </list>
    /// When <c>AllowInsecure</c> is still needed, prefer a scoped
    /// <c>Pkcs11Workspace.UsePolicy(CryptoPolicy.AllowInsecure)</c> lease over opening a whole workspace
    /// under it.
    /// </remarks>
    public static ICryptoPolicy AllowInsecure { get; } = new AllowInsecurePolicy();
}
