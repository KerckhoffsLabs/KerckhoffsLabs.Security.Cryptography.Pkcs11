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
    /// documented deny list — is at <c>docs/guide/policies/recommended.md</c> in the repository. To allow a reviewed
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
    /// the documented (but non-enforcing) deny list. A session opened under this policy refuses every
    /// <c>UsePolicy</c> override.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This restricts what the library sends to the token. It does <b>not</b> make an application FIPS 140-3
    /// compliant — that also requires a validated cryptographic module operating in its approved mode.
    /// </para>
    /// <para>
    /// The full generated catalogue — every allowed mechanism/hash/curve/KDF/PRF with its NIST citation and
    /// the documented deny list — is at <c>docs/guide/policies/nist-approved.md</c> in the repository.
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
    /// Allows only the NSA CNSA 2.0 algorithms at their CNSA 2.0 sizes: AES-256 in GCM (128-bit tag only) and
    /// KW/KWP, SHA-384/512 and HMAC over them, SP 800-108 and HKDF over SHA-384/512, ML-KEM-1024, ML-DSA-87,
    /// single-level LMS (HSS) and XMSS. Unlike the other built-ins it inspects keys: AES keys must be 256 bits,
    /// generic-secret, HKDF and HMAC keys at least 256 bits, ML-KEM keys ML-KEM-1024, ML-DSA keys ML-DSA-87 and
    /// HSS keys single-level, both in a template and on every use of an existing key; a key the token creates is
    /// read back and destroyed if it fails. <b>Refuses</b> RSA, DSA, ECDSA, EdDSA, ECDH, X25519/X448, DH, SLH-DSA,
    /// HashML-DSA, XMSS^MT, ChaCha20, every other AES mode (CBC, CTR, ECB, CCM, CMAC, GMAC, …),
    /// <c>CKM_AES_KEY_WRAP_PAD</c>, DES/TDEA, SHA-1, SHA-224, SHA-256, SHA-512/t, SHA-3, PBKDF2, every key type
    /// outside the list above, and a key whose type, length, parameter set or HSS levels the token does not report.
    /// <b>Denies by default:</b> anything not on its allow-list, including every vendor-defined mechanism, is
    /// refused. Also refuses non-sensitive key templates and reading secret key material off the token. A session
    /// opened under this policy refuses every <c>UsePolicy</c> override.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This restricts what the library sends to the token. It is <b>not</b> a CNSA 2.0 certification or
    /// validation of the application or the token. The CNSA 2.0 citations come from secondary sources and are
    /// pending verification against the NSA documents.
    /// </para>
    /// <para>
    /// The full generated catalogue, with every allowed and documented-refused item and its alternative, is at
    /// <c>docs/guide/policies/cnsa-2.0.md</c> in the repository.
    /// </para>
    /// <para>Known limits:</para>
    /// <list type="bullet">
    /// <item><description>LMS (HSS) and XMSS are allowed for any signing. CNSA 2.0 intends them for software and
    /// firmware signing; the policy cannot see what is signed, so restricting them is the application's job.</description></item>
    /// <item><description>XMSS parameter sets are not checked.</description></item>
    /// <item><description>It fails closed: a key whose attributes the token does not report is refused, which may
    /// refuse a compliant key on a token that hides them.</description></item>
    /// <item><description>Each keyed operation costs one or two extra <c>C_GetAttributeValue</c> calls.</description></item>
    /// <item><description><c>C_SetOperationState</c> restores a saved operation whose own mechanism and key are not
    /// inspected; only the key handles passed to it are.</description></item>
    /// <item><description>Keys returned through TLS/SSL3 key-and-MAC parameters are not judged after creation.
    /// Cnsa20 refuses those mechanisms, but a policy derived from it that allows them again would not judge those keys.</description></item>
    /// </list>
    /// <para>
    /// A policy derived with <see cref="ComposedCryptoPolicy.ToBuilder(string)"/> gets its own name, keeps the key
    /// inspection and keeps <see cref="ICryptoPolicy.AllowsOverride"/> false unless changed; <c>CryptoPolicy.Cnsa20</c>
    /// itself never changes.
    /// </para>
    /// </remarks>
    public static ComposedCryptoPolicy Cnsa20 { get; } = Cnsa20Definition.Create();

    /// <summary>
    /// Allows everything, including broken algorithms and plaintext key export. For legacy interop only.
    /// </summary>
    /// <remarks>
    /// Reach for the narrowest opt-in first. Most single needs have one on the builder that
    /// <c>Recommended.ToBuilder(name)</c> returns, and every other Recommended rule keeps applying:
    /// <list type="bullet">
    /// <item><description>a legacy mechanism — <see cref="CryptoPolicyBuilder.AllowMechanism(Common.CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>;</description></item>
    /// <item><description>a weak EC curve — <see cref="CryptoPolicyBuilder.AllowCurve(Pkcs11ECCurve, string)"/>;</description></item>
    /// <item><description>a key-agreement KDF — <see cref="CryptoPolicyBuilder.AllowKeyAgreementKdf"/>.</description></item>
    /// </list>
    /// When <c>AllowInsecure</c> is still needed, prefer a scoped
    /// <c>Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)</c> lease over opening a whole session
    /// under it.
    /// <para>
    /// It lets PKCS#1 v1.5 decryption (<c>CKM_RSA_PKCS</c>) through. On a token that implements implicit
    /// rejection, invalid padding then returns a synthetic plaintext instead of failing, so never treat the
    /// success or failure of that decryption as a signal; see
    /// <see href="https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#pkcs1-implicit-rejection">KLPKCS11008</see>.
    /// </para>
    /// </remarks>
    public static ICryptoPolicy AllowInsecure { get; } = new AllowInsecurePolicy();
}
