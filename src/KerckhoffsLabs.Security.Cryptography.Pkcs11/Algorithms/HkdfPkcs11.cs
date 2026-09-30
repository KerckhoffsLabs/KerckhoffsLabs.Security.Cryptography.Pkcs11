using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// RFC 5869 HKDF run on a PKCS#11 token (<c>CKM_HKDF_DERIVE</c>, PKCS#11 v3.0), shaped after the BCL's
/// static <see cref="HKDF"/> class: the same method names, parameter order, overloads and argument
/// validation, with the secret input — the IKM, or the PRK for <c>Expand</c> — a token-resident
/// <see cref="Pkcs11Key"/> instead of bytes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two surfaces.</b> The <c>DeriveKey</c> / <c>Extract</c> / <c>Expand</c> overloads that return or
/// fill bytes mirror <see cref="HKDF"/> and produce the same output for the same inputs. Reading that
/// output means taking key material off the token, so under the default policy they throw
/// <see cref="CryptoPolicyViolationException"/> unless the workspace's policy allows it, e.g.
/// <c>CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, reason)</c>. The additions —
/// <see cref="DeriveKey(HashAlgorithmName, Pkcs11Key, ObjectTemplate, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>,
/// <see cref="ExtractKey"/> and <see cref="ExpandKey"/> — keep the result on the token as a
/// <see cref="Pkcs11Key"/> and need no override: prefer them whenever the derived material only has to
/// be used, not exported (for example an ECDH shared secret expanded into AES keys).
/// </para>
/// <para>
/// <b>Hashes.</b> SHA-256, SHA-384, SHA-512 and SHA3-256/384/512, run as the matching
/// <c>CKM_*_HMAC</c> PRF. Unlike <see cref="HKDF"/>, SHA-1 and MD5 are refused with
/// <see cref="NotSupportedException"/>, as the library's other KDF adapters do. Any other name throws
/// <see cref="ArgumentOutOfRangeException"/>, as <see cref="HKDF"/> does.
/// </para>
/// <para>
/// <b>Keys.</b> The IKM and PRK must be <see cref="CKK.CKK_GENERIC_SECRET"/> or <see cref="CKK.CKK_HKDF"/>
/// keys with <c>CKA_DERIVE</c> set. An empty or <see langword="null"/> salt is RFC 5869's default
/// (<c>HashLen</c> zero bytes), sent as <c>CKF_HKDF_SALT_NULL</c>. Keys are borrowed, never disposed.
/// </para>
/// </remarks>
public static class HkdfPkcs11
{
    /// <summary>A supported HKDF hash: its PRF mechanism and output length.</summary>
    private readonly record struct Prf(CKM Mechanism, int HashLength)
    {
        /// <summary>RFC 5869 §2.3: the output keying material is at most 255 · HashLen bytes.</summary>
        public int MaxOutputLength => 255 * HashLength;
    }

    /// <summary>
    /// Performs the HKDF extract and expand steps on the token. Mirrors
    /// <see cref="HKDF.DeriveKey(HashAlgorithmName, byte[], int, byte[], byte[])"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="outputLength">The number of bytes to derive.</param>
    /// <param name="salt">The optional salt; <see langword="null"/> or empty means RFC 5869's default.</param>
    /// <param name="info">The optional context and application-specific information.</param>
    /// <returns>The output keying material.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not positive or exceeds 255 · the hash length; or <paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, int outputLength, byte[]? salt = null, byte[]? info = null)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        RequireHkdfKey(ikm, nameof(ikm));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);
        Prf prf = PrfFor(hashAlgorithmName);
        if (outputLength > prf.MaxOutputLength)
            throw new ArgumentOutOfRangeException(nameof(outputLength), MaxOutputMessage(prf));

        return DeriveBytes(ikm, HkdfMechanism(HkdfOperation.ExtractAndExpand, prf, salt, info), outputLength);
    }

    /// <summary>
    /// Performs the HKDF extract and expand steps on the token, filling <paramref name="output"/>.
    /// Mirrors <see cref="HKDF.DeriveKey(HashAlgorithmName, ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="output">Receives the output keying material; its length is the length derived.</param>
    /// <param name="salt">The salt; empty means RFC 5869's default.</param>
    /// <param name="info">The context and application-specific information.</param>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key; or <paramref name="output"/> is empty or longer than 255 · the hash length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static void DeriveKey(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        RequireHkdfKey(ikm, nameof(ikm));
        Prf prf = PrfFor(hashAlgorithmName);
        RequireOutputLength(output, prf);

        ikm.DeriveAndExportSecret(HkdfMechanism(HkdfOperation.ExtractAndExpand, prf, salt, info), output);
    }

    /// <summary>
    /// Performs the HKDF extract and expand steps on the token and keeps the result there, shaped by
    /// <paramref name="template"/>. Has no <see cref="HKDF"/> counterpart; needs no policy override
    /// unless the template itself asks for an extractable or non-sensitive key.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="template">The derived key's template; its <c>CKA_VALUE_LEN</c> (or key type) sets the length derived.</param>
    /// <param name="salt">The salt; empty means RFC 5869's default.</param>
    /// <param name="info">The context and application-specific information.</param>
    /// <returns>The derived key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> or <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses the template or the mechanism.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public static Pkcs11Key DeriveKey(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, ObjectTemplate template,
        ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        ArgumentNullException.ThrowIfNull(template);
        RequireHkdfKey(ikm, nameof(ikm));
        Prf prf = PrfFor(hashAlgorithmName);

        return ikm.Derive(HkdfMechanism(HkdfOperation.ExtractAndExpand, prf, salt, info), template);
    }

    /// <summary>
    /// Performs the HKDF extract step on the token and returns the pseudo-random key. Mirrors
    /// <see cref="HKDF.Extract(HashAlgorithmName, byte[], byte[])"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="salt">The optional salt; <see langword="null"/> or empty means RFC 5869's default.</param>
    /// <returns>The pseudo-random key, one hash length long.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static byte[] Extract(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        RequireHkdfKey(ikm, nameof(ikm));
        Prf prf = PrfFor(hashAlgorithmName);

        return DeriveBytes(ikm, HkdfMechanism(HkdfOperation.ExtractOnly, prf, salt, default), prf.HashLength);
    }

    /// <summary>
    /// Performs the HKDF extract step on the token, writing the pseudo-random key to
    /// <paramref name="prk"/>. Mirrors
    /// <see cref="HKDF.Extract(HashAlgorithmName, ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="salt">The salt; empty means RFC 5869's default.</param>
    /// <param name="prk">Receives the pseudo-random key; must be at least one hash length long.</param>
    /// <returns>The number of bytes written to <paramref name="prk"/>: the hash length.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key; or <paramref name="prk"/> is shorter than the hash length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static int Extract(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        RequireHkdfKey(ikm, nameof(ikm));
        Prf prf = PrfFor(hashAlgorithmName);
        if (prk.Length < prf.HashLength)
            throw new ArgumentException(PrkTooShortMessage(prf), nameof(prk));

        ikm.DeriveAndExportSecret(HkdfMechanism(HkdfOperation.ExtractOnly, prf, salt, default), prk[..prf.HashLength]);
        return prf.HashLength;
    }

    /// <summary>
    /// Performs the HKDF extract step on the token and keeps the pseudo-random key there, as a
    /// sensitive, non-extractable session key usable only for derivation — the input
    /// <see cref="Expand(HashAlgorithmName, Pkcs11Key, int, byte[])"/> and <see cref="ExpandKey"/>
    /// take. Has no <see cref="HKDF"/> counterpart and needs no policy override.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="ikm">The input keying material: a generic-secret or HKDF key with <c>CKA_DERIVE</c>.</param>
    /// <param name="salt">The salt; empty means RFC 5869's default.</param>
    /// <returns>The pseudo-random key, one hash length long.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ikm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ikm"/> is not a generic-secret or HKDF key.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public static Pkcs11Key ExtractKey(HashAlgorithmName hashAlgorithmName, Pkcs11Key ikm, ReadOnlySpan<byte> salt = default)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        RequireHkdfKey(ikm, nameof(ikm));
        Prf prf = PrfFor(hashAlgorithmName);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(prf.HashLength)
            .Derive()
            .Sensitive()
            .NonExtractable()
            .OnToken(false)
            .Build();
        return ikm.Derive(HkdfMechanism(HkdfOperation.ExtractOnly, prf, salt, default), template);
    }

    /// <summary>
    /// Performs the HKDF expand step on the token. Mirrors
    /// <see cref="HKDF.Expand(HashAlgorithmName, byte[], int, byte[])"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="prk">The pseudo-random key (for example from <see cref="ExtractKey"/>): a generic-secret or HKDF key with <c>CKA_DERIVE</c>, at least one hash length long.</param>
    /// <param name="outputLength">The number of bytes to derive.</param>
    /// <param name="info">The optional context and application-specific information.</param>
    /// <returns>The output keying material.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="prk"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="prk"/> is not a generic-secret or HKDF key, or the token reports it shorter than the hash length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outputLength"/> is not positive or exceeds 255 · the hash length; or <paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static byte[] Expand(HashAlgorithmName hashAlgorithmName, Pkcs11Key prk, int outputLength, byte[]? info = null)
    {
        ArgumentNullException.ThrowIfNull(prk);
        RequireHkdfKey(prk, nameof(prk));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);
        Prf prf = PrfFor(hashAlgorithmName);
        if (outputLength > prf.MaxOutputLength)
            throw new ArgumentOutOfRangeException(nameof(outputLength), MaxOutputMessage(prf));
        RequirePrkLength(prk, prf);

        return DeriveBytes(prk, HkdfMechanism(HkdfOperation.ExpandOnly, prf, default, info), outputLength);
    }

    /// <summary>
    /// Performs the HKDF expand step on the token, filling <paramref name="output"/>. Mirrors
    /// <see cref="HKDF.Expand(HashAlgorithmName, ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="prk">The pseudo-random key (for example from <see cref="ExtractKey"/>): a generic-secret or HKDF key with <c>CKA_DERIVE</c>, at least one hash length long.</param>
    /// <param name="output">Receives the output keying material; its length is the length derived.</param>
    /// <param name="info">The context and application-specific information.</param>
    /// <exception cref="ArgumentNullException"><paramref name="prk"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="prk"/> is not a generic-secret or HKDF key, or the token reports it shorter than the hash length; or <paramref name="output"/> is empty or longer than 255 · the hash length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading the derived value off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying token calls.</exception>
    public static void Expand(HashAlgorithmName hashAlgorithmName, Pkcs11Key prk, Span<byte> output, ReadOnlySpan<byte> info)
    {
        ArgumentNullException.ThrowIfNull(prk);
        RequireHkdfKey(prk, nameof(prk));
        Prf prf = PrfFor(hashAlgorithmName);
        RequireOutputLength(output, prf);
        RequirePrkLength(prk, prf);

        prk.DeriveAndExportSecret(HkdfMechanism(HkdfOperation.ExpandOnly, prf, default, info), output);
    }

    /// <summary>
    /// Performs the HKDF expand step on the token and keeps the result there, shaped by
    /// <paramref name="template"/>. Has no <see cref="HKDF"/> counterpart; needs no policy override
    /// unless the template itself asks for an extractable or non-sensitive key.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash of the HKDF PRF.</param>
    /// <param name="prk">The pseudo-random key (for example from <see cref="ExtractKey"/>): a generic-secret or HKDF key with <c>CKA_DERIVE</c>, at least one hash length long.</param>
    /// <param name="template">The derived key's template; its <c>CKA_VALUE_LEN</c> (or key type) sets the length derived.</param>
    /// <param name="info">The context and application-specific information.</param>
    /// <returns>The derived key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="prk"/> or <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="prk"/> is not a generic-secret or HKDF key, or the token reports it shorter than the hash length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hashAlgorithmName"/> is not a known hash.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithmName"/> is SHA-1 or MD5.</exception>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses the template or the mechanism.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public static Pkcs11Key ExpandKey(HashAlgorithmName hashAlgorithmName, Pkcs11Key prk, ObjectTemplate template, ReadOnlySpan<byte> info = default)
    {
        ArgumentNullException.ThrowIfNull(prk);
        ArgumentNullException.ThrowIfNull(template);
        RequireHkdfKey(prk, nameof(prk));
        Prf prf = PrfFor(hashAlgorithmName);
        RequirePrkLength(prk, prf);

        return prk.Derive(HkdfMechanism(HkdfOperation.ExpandOnly, prf, default, info), template);
    }

    // Unknown names throw ArgumentOutOfRangeException on hashAlgorithmName, as HKDF does. SHA-1 and MD5,
    // which HKDF accepts, are refused: the library's KDF adapters do not offer broken hashes as a PRF.
    private static Prf PrfFor(HashAlgorithmName hashAlgorithmName) => hashAlgorithmName.Name switch
    {
        "SHA256" => new Prf(CKM.CKM_SHA256_HMAC, 32),
        "SHA384" => new Prf(CKM.CKM_SHA384_HMAC, 48),
        "SHA512" => new Prf(CKM.CKM_SHA512_HMAC, 64),
        "SHA3-256" => new Prf(CKM.CKM_SHA3_256_HMAC, 32),
        "SHA3-384" => new Prf(CKM.CKM_SHA3_384_HMAC, 48),
        "SHA3-512" => new Prf(CKM.CKM_SHA3_512_HMAC, 64),
        "SHA1" or "MD5" => throw new NotSupportedException(
            $"{hashAlgorithmName.Name} is broken and not offered as an HKDF PRF; use SHA256, SHA384, SHA512 or SHA3."),
        _ => throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName), hashAlgorithmName.Name,
            "HKDF supports SHA256, SHA384, SHA512, SHA3-256, SHA3-384 and SHA3-512."),
    };

    private static Mechanism HkdfMechanism(HkdfOperation operation, Prf prf, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
    {
        // CKF_HKDF_SALT_NULL is RFC 5869's default salt (HashLen zero bytes), which is what HKDF uses for
        // a null or empty salt. Sending an empty CKF_HKDF_SALT_DATA instead is refused by some tokens.
        CkmHkdfParams parameters = salt.IsEmpty
            ? CkmHkdfParams.WithoutSalt(operation, prf.Mechanism, info)
            : CkmHkdfParams.WithSalt(operation, prf.Mechanism, salt, info);
        return new Mechanism(CKM.CKM_HKDF_DERIVE, parameters);
    }

    private static void RequireHkdfKey(Pkcs11Key key, string paramName)
    {
        if (key.KeyType is not (CKK.CKK_GENERIC_SECRET or CKK.CKK_HKDF))
            throw new ArgumentException(
                $"Expected a generic-secret or HKDF key (CKK_GENERIC_SECRET or CKK_HKDF), got {key.KeyType}.", paramName);
    }

    private static void RequireOutputLength(Span<byte> output, Prf prf)
    {
        if (output.IsEmpty)
            throw new ArgumentException("Destination is too short.", nameof(output));
        if (output.Length > prf.MaxOutputLength)
            throw new ArgumentException(MaxOutputMessage(prf), nameof(output));
    }

    // HKDF refuses a PRK shorter than the hash length. A token key's length is known only when the
    // token reports CKA_VALUE_LEN; when it does not, the token judges the key itself.
    private static void RequirePrkLength(Pkcs11Key prk, Prf prf)
    {
        using var attrs = prk.GetAttributeValue(CKA.CKA_VALUE_LEN);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            return;
        if (attrs[0].GetValueAsUlong() < (ulong)prf.HashLength)
            throw new ArgumentException(PrkTooShortMessage(prf), nameof(prk));
    }

    private static byte[] DeriveBytes(Pkcs11Key key, Mechanism mechanism, int length)
    {
        byte[] output = new byte[length];
        key.DeriveAndExportSecret(mechanism, output);
        return output;
    }

    private static string MaxOutputMessage(Prf prf)
        => $"Output keying material length can be at most {prf.MaxOutputLength} bytes (255 * hash length).";

    private static string PrkTooShortMessage(Prf prf)
        => $"The pseudo-random key length must be at least {prf.HashLength} bytes.";
}
