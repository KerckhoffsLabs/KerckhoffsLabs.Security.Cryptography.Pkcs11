namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>The built-in <see cref="ICryptoPolicy"/> instances.</summary>
public static class CryptoPolicy
{
    /// <summary>
    /// The default policy. Refuses broken or dangerous algorithms (MD5, SHA-1 signatures, DES/3DES, ECB,
    /// unauthenticated AES modes, RSA PKCS#1 v1.5 encryption, …), RSA keys under 2048 bits, EC curves under
    /// 128-bit security, non-sensitive key templates, <c>CKD_NULL</c>, and reading secret key material off
    /// the token. Mechanisms it does not know (including vendor-defined ones) are allowed.
    /// </summary>
    public static ICryptoPolicy SecureOnly { get; } = new SecureOnlyPolicy();

    /// <summary>
    /// Allows only NIST-approved security functions (SP 800-131A / SP 800-140C, FIPS 186-5, FIPS 203–205),
    /// with SP 800-131A "legacy use" permitted for TDEA decryption/unwrapping, TDEA CMAC verification, and
    /// SHA-1/DSA signature verification. RSA PKCS#1 v1.5 encryption and decryption/unwrap are refused. AES
    /// key wrapping is approved only via KW/KWP (<c>CKM_AES_KEY_WRAP</c>, <c>CKM_AES_KEY_WRAP_KWP</c>,
    /// <c>CKM_AES_KEY_WRAP_PAD</c>) or the GCM/CCM modes; other AES modes encrypt and decrypt data but may
    /// not wrap or unwrap keys. Refuses every mechanism not on its list, including vendor-defined ones. A
    /// workspace opened under this policy refuses every <c>UsePolicy</c> override.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This restricts what the library sends to the token. It does <b>not</b> make an application FIPS 140-3
    /// compliant — that also requires a validated cryptographic module operating in its approved mode.
    /// </para>
    /// <para>Known limits — the policy judges requests, not the token's contents:</para>
    /// <list type="bullet">
    /// <item><description>It judges mechanisms, parameters and <i>requested</i> key sizes and curves. It does
    /// not inspect keys already on the token: using an existing RSA-1024 or Brainpool key is not refused.</description></item>
    /// <item><description>The EC curve is checked only by <c>Pkcs11Workspace.GenerateEcKeyPair</c>. Generating
    /// an EC key pair through the generic key-pair overload
    /// <see cref="Pkcs11Workspace.GenerateKey(Mechanism, Objects.ObjectTemplate, Objects.ObjectTemplate)"/> with
    /// <c>CKM_EC_KEY_PAIR_GEN</c> does not have its curve checked.</description></item>
    /// <item><description>ECDH with an existing X25519/X448 (Montgomery) key is not detected; only generating
    /// such keys is refused.</description></item>
    /// <item><description>Raw <c>CKM_RSA_PKCS</c> signing and raw <c>CKM_ECDSA</c> cannot see which digest the
    /// caller pre-computed, so the digest is not checked.</description></item>
    /// <item><description>The PRF inside SP 800-108 and PBKDF2 parameters, and the KDF inside
    /// <c>CKM_ECDH1_DERIVE</c> parameters passed through <c>Pkcs11Key.Derive</c>, are not inspected.</description></item>
    /// <item><description><c>CKM_AES_KEY_WRAP_PAD</c> is approved, but its meaning is vendor-dependent: some
    /// tokens implement RFC 5649 (KWP), others KW over PKCS#7-padded input, which is not an SP 800-38F method.
    /// Prefer <c>CKM_AES_KEY_WRAP_KWP</c> where the token supports it.</description></item>
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
