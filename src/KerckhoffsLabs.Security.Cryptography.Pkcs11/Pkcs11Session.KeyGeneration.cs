using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Session
{
    // === Secure-default key-generation helpers =============================

    /// <summary>
    /// Generates an AES secret key — sensitive, non-extractable, usable for encryption and
    /// decryption only. Session-only unless <paramref name="persistOnToken"/> is set.
    /// </summary>
    /// <remarks>
    /// Deliberately does not grant <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c>: a key that can both decrypt
    /// caller-supplied ciphertext and wrap other keys is a wrap-oracle (wrap an extractable key,
    /// then decrypt the blob to read it in the clear) and an unwrap-injection vector (encrypt a
    /// chosen plaintext, then unwrap it as a "wrapped key" of known value). Use
    /// <see cref="GenerateAesKeyEncryptionKey"/> for a dedicated, wrap/unwrap-only KEK.
    /// </remarks>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to the key. Default none.</param>
    /// <param name="persistOnToken">If true, the key is a token object (<c>CKA_TOKEN=true</c>, persistent). Default false (session-only).</param>
    /// <returns>The generated AES key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="bitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateAesKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), "AES key length must be 128, 192, or 256 bits.");

        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(bitLength / 8)
            .Sensitive().NonExtractable()
            .Encrypt().Decrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
            builder = builder.Label(label);

        using var template = builder.Build();
        var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an AES key-encryption key (KEK) — sensitive, non-extractable, usable only to wrap
    /// and unwrap other keys via <see cref="Pkcs11Key.Wrap"/>/<see cref="Pkcs11Key.Unwrap"/>.
    /// Session-only unless <paramref name="persistOnToken"/> is set.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — see <see cref="GenerateAesKey"/>
    /// for why combining data-encryption and key-wrapping roles on one key is a wrap-oracle risk.
    /// Every key unwrapped through this KEK is forced sensitive/non-extractable via
    /// <c>CKA_UNWRAP_TEMPLATE</c>, regardless of what the caller's unwrap template requests; this
    /// KEK will only wrap keys already marked <c>CKA_SENSITIVE</c> via <c>CKA_WRAP_TEMPLATE</c>.
    /// </remarks>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to the key. Default none.</param>
    /// <param name="persistOnToken">If true, the key is a token object (<c>CKA_TOKEN=true</c>, persistent). Default false (session-only).</param>
    /// <returns>The generated AES key-encryption key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="bitLength"/> is not 128, 192, or 256.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call.</exception>
    public Pkcs11Key GenerateAesKeyEncryptionKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bitLength is not 128 and not 192 and not 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), "AES key length must be 128, 192, or 256 bits.");

        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(bitLength / 8)
            .Sensitive().NonExtractable()
            .Wrap().Unwrap()
            .WrapTemplate(t => t.Sensitive())
            .UnwrapTemplate(t => t.Sensitive().NonExtractable())
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
            builder = builder.Label(label);

        using var template = builder.Build();
        var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an RSA signing key pair. The private key is sensitive, non-extractable, and usable
    /// only for signing; the public key only for verification. The public exponent is fixed at
    /// 65537. The returned key carries both handles.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — see
    /// <see cref="GenerateRsaKeyTransportKeyPair"/> for a dedicated encryption pair, and for why
    /// combining signing and encryption roles on one RSA key pair is unsafe.
    /// </remarks>
    /// <param name="modulusBits">RSA modulus size in bits. Default 4096. Sizes below 2048 (NIST SP
    /// 800-131A) are refused unless the session's <see cref="Policy"/> permits it.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated RSA key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="modulusBits"/> is not positive.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="modulusBits"/> is &lt; 2048 and the session's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateRsaSigningKeyPair(int modulusBits = 4096, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulusBits);
        // The sub-2048 secure-defaults gate is enforced once in the session layer's crypto policy check,
        // so it applies uniformly to this helper and to direct low-level GenerateKey callers.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01])
            .Verify()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable()
            .Sign()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }

    /// <summary>
    /// Generates an RSA key-transport key pair. The private key is sensitive, non-extractable, and
    /// usable only to decrypt; the public key only to encrypt (RSA-OAEP key transport). The public
    /// exponent is fixed at 65537. The returned key carries both handles.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>CKA_SIGN</c>/<c>CKA_VERIFY</c> and <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c>
    /// — see <see cref="GenerateRsaSigningKeyPair"/> for the signing counterpart. A caller who
    /// specifically needs RSA <c>C_WrapKey</c>/<c>C_UnwrapKey</c> semantics (rather than encrypting
    /// data directly) should build that template explicitly via
    /// <see cref="GenerateKeyPair(Mechanism, ObjectTemplate, ObjectTemplate)"/>.
    /// </remarks>
    /// <param name="modulusBits">RSA modulus size in bits. Default 4096. Sizes below 2048 (NIST SP
    /// 800-131A) are refused unless the session's <see cref="Policy"/> permits it.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated RSA key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="modulusBits"/> is not positive.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="modulusBits"/> is &lt; 2048 and the session's <see cref="Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateRsaKeyTransportKeyPair(int modulusBits = 4096, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(modulusBits);
        // The sub-2048 secure-defaults gate is enforced once in the session layer's crypto policy check,
        // so it applies uniformly to this helper and to direct low-level GenerateKey callers.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01])
            .Encrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable()
            .Decrypt()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }

    /// <summary>
    /// Generates an EC key pair on a NIST prime curve. The private key is sensitive,
    /// non-extractable, and usable for signing and ECDH derivation.
    /// </summary>
    /// <param name="curve">Named curve from <see cref="Pkcs11ECCurve.NamedCurves"/> (or <see cref="Pkcs11ECCurve.CreateFromValue(string, string?, int?)"/>).
    /// Defaults to <see cref="Pkcs11ECCurve.NamedCurves.NistP256"/> when omitted. The token must support the curve.</param>
    /// <param name="label">Optional <c>CKA_LABEL</c> applied to both halves. Default none.</param>
    /// <param name="persistOnToken">If true, both halves are token objects (persistent). Default false.</param>
    /// <returns>The generated EC key pair.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the session has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="curve"/> is the default (uninitialized) <see cref="Pkcs11ECCurve"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">The session's <see cref="Policy"/> does not allow
    /// the curve (under the default policy: any curve not on its allow-list, including every curve below
    /// 128-bit security).</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKeyPair</c> call.</exception>
    public Pkcs11Key GenerateEcKeyPair(Pkcs11ECCurve? curve = null, string? label = null, bool persistOnToken = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Pkcs11ECCurve resolved = curve ?? Pkcs11ECCurve.NamedCurves.NistP256;
        if (resolved.IsDefault)
            throw new ArgumentException("An EC curve must be specified.", nameof(curve));
        // The curve allow-list is enforced by the session's GenerateKeyPair, which every EC key-pair
        // generation reaches, so there is no separate check here.

        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(resolved.GetEcParams())
            .Verify()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Sensitive().NonExtractable()
            .Sign().Derive()
            .OnToken(persistOnToken)
            .Attribute(CKA.CKA_MODIFIABLE, false);
        if (label is not null)
        {
            pub = pub.Label(label);
            priv = priv.Label(label);
        }

        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        return GenerateKeyPair(mechanism, pubTemplate, privTemplate);
    }
}
