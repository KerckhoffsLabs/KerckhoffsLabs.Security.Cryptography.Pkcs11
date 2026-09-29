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
    /// non-enforcing) deny list. Also refuses RSA keys under 2048 bits, non-sensitive key templates, and
    /// reading secret key material off the token.
    /// </summary>
    /// <remarks>
    /// The full generated catalogue — every allowed mechanism/hash/curve/KDF/PRF with its rationale, the
    /// documented deny list, and <c>SecureOnlyPolicy.WithAllowedMechanism(...)</c>, the extension point for
    /// adding a reviewed mechanism — is at <c>docs/policies/secure-only.md</c> in the repository.
    /// </remarks>
    public static SecureOnlyPolicy SecureOnly { get; } = new SecureOnlyPolicy();

    /// <summary>
    /// Allows only NIST-approved security functions (SP 800-131A / SP 800-140C, FIPS 186-5, FIPS 203–205),
    /// with SP 800-131A "legacy use" permitted for TDEA decryption/unwrapping, TDEA CMAC verification, and
    /// SHA-1/DSA signature verification. RSA PKCS#1 v1.5 encryption and decryption/unwrap are refused. AES
    /// key wrapping is approved only via KW/KWP (<c>CKM_AES_KEY_WRAP</c>, <c>CKM_AES_KEY_WRAP_KWP</c>) or the
    /// GCM/CCM modes; <c>CKM_AES_KEY_WRAP_PAD</c>, whose padding is vendor-defined, is refused. Other AES
    /// modes encrypt and decrypt data but may not wrap or unwrap keys. <b>Denies by default:</b> refuses every mechanism, hash, curve, KDF and PRF
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
    /// the documented deny list — is at <c>docs/policies/fips-only.md</c> in the repository.
    /// </para>
    /// <para>Known limits — the policy judges requests, not the token's contents:</para>
    /// <list type="bullet">
    /// <item><description>It judges mechanisms, parameters and <i>requested</i> key sizes and curves. It does
    /// not inspect the size or curve of keys already on the token: using an existing RSA-1024 or Brainpool key
    /// is not refused. (For ECDH the existing key's type is checked, so an X25519/X448 key is refused.)</description></item>
    /// <item><description>Raw <c>CKM_RSA_PKCS</c> signing and raw <c>CKM_ECDSA</c> cannot see which digest the
    /// caller pre-computed, so the digest is not checked.</description></item>
    /// </list>
    /// </remarks>
    public static ICryptoPolicy FipsOnly { get; } = new FipsOnlyPolicy();

    /// <summary>
    /// Allows everything, including broken algorithms and plaintext key export. For legacy interop only;
    /// prefer a scoped <c>Pkcs11Workspace.UsePolicy(CryptoPolicy.AllowInsecure)</c> lease over opening a
    /// whole workspace under it.
    /// </summary>
    public static ICryptoPolicy AllowInsecure { get; } = new AllowInsecurePolicy();
}
