using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned RSA provider backed by a PKCS#11 <c>Pkcs11Key</c>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="RSA"/> so callers can pass this instance anywhere a BCL
/// <c>RSA</c> is accepted (e.g. <c>RSACertificateExtensions</c>, ASP.NET Core signing).
/// </para>
/// <para>
/// On .NET 10, the BCL splits its sign/verify dispatch by entry-point overload:
/// the <c>byte[]</c> path goes through <c>SignData(byte[], int, int, …)</c> /
/// <c>VerifyData(byte[], int, int, byte[], …)</c>, while the span path goes through
/// <c>TrySignData(ReadOnlySpan, …)</c> / <c>VerifyData(ReadOnlySpan, ReadOnlySpan, …)</c>.
/// Neither path routes through the other, so we override both. All overrides forward
/// the full data bytes to PKCS#11 via the combined hash+sign mechanism (e.g.
/// <c>CKM_SHA256_RSA_PKCS</c>) — the token hashes and signs in a single <c>C_Sign</c> call,
/// avoiding the gated <c>CKM_RSA_PKCS</c> raw-sign mechanism.
/// </para>
/// </remarks>
public sealed class RSAPkcs11 : RSA
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a PKCS#11 RSA key as a BCL <see cref="RSA"/> instance. Does not take
    /// ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_RSA"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an RSA key.</exception>
    public RSAPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_RSA)
            throw new ArgumentException(
                $"Expected an RSA key, got {key.KeyType}.", nameof(key));
        _key = key;

        // Reflect the token key's real modulus size. Best-effort: the RSA base constructor leaves
        // KeySize=0 (via KeySizeValue), which we keep if the token exposes neither attribute —
        // callers relying on KeySize/LegalKeySizes would already be broken in that case.
        int? bits = TryReadKeySizeBits(key);
        if (bits is int b)
        {
            KeySizeValue = b;
            LegalKeySizesValue = [new KeySizes(b, b, 0)];
        }
    }

    // A token-resident key has exactly one size — it can't be resized — so LegalKeySizesValue
    // reports that single size rather than a generic range the token may not actually support.
    private static int? TryReadKeySizeBits(Pkcs11Key key)
    {
        try
        {
            return key.KeySize;
        }
        catch (Pkcs11Exception)
        {
            // C_GetAttributeValue failed — leave KeySize at the RSA base-class default.
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // Signing — forward full data to PKCS#11 using combined hash+sign mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Span entry-point — the .NET 10 BCL routes <c>SignData(ReadOnlySpan&lt;byte&gt;, …)</c>
    /// here. The full un-hashed data is forwarded to PKCS#11; the token hashes and signs
    /// in one <c>C_Sign</c> call.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is an unsupported signature padding, or <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown for a broken-hash signature (e.g. SHA-1, which maps to <c>CKM_SHA1_RSA_PKCS</c> / <c>CKM_SHA1_RSA_PKCS_PSS</c>) or a SHA-224 one (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it; strong-hash PKCS#1 v1.5 and PSS are allowed by default.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override bool TrySignData(
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        out int bytesWritten)
    {
        ArgumentNullException.ThrowIfNull(padding);
        var mech = SignMechanismFor(hashAlgorithm, padding);
        byte[] sig = _key.Sign(mech, data);
        if (sig.Length > destination.Length)
        {
            bytesWritten = 0;
            return false;
        }
        sig.CopyTo(destination);
        bytesWritten = sig.Length;
        return true;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Byte-array entry-point — the .NET 10 BCL routes <c>SignData(byte[], …)</c> through
    /// here, NOT through <see cref="TrySignData"/>. Without this override the default
    /// implementation would hash in managed code and sign the digest with
    /// <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/>, through the raw mechanisms
    /// rather than the combined one that hashes on the token.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> or <paramref name="padding"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/> is negative or outside the bounds of <paramref name="data"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is an unsupported signature padding, or <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown for a broken-hash signature (e.g. SHA-1) or a SHA-224 one (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] SignData(
        byte[] data,
        int offset,
        int count,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        if (offset < 0 || count < 0 || offset > data.Length - count)
            throw new ArgumentOutOfRangeException(nameof(offset));

        var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Sign(mech, data.AsSpan(offset, count));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Hashes <paramref name="data"/> in managed code, as the BCL does, and signs the digest with
    /// <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/>, under its policy.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> or <paramref name="padding"/> is <see langword="null"/>, or <paramref name="hashAlgorithm"/> has no name.</exception>
    /// <exception cref="NotSupportedException"><paramref name="padding"/> or <paramref name="hashAlgorithm"/> is not supported.</exception>
    /// <exception cref="PlatformNotSupportedException"><paramref name="hashAlgorithm"/> is a SHA-3 hash the platform cannot compute (<see cref="SHA3_256.IsSupported"/> and its siblings).</exception>
    /// <exception cref="CryptoPolicyViolationException">The session's policy refuses the hash or the mechanism.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] SignData(Stream data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ThrowIfNoHashName(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(padding);

        GuardHash(hashAlgorithm, CryptoOperation.Sign);
        return SignHash(base.HashData(data, hashAlgorithm), hashAlgorithm, padding);
    }

    // -----------------------------------------------------------------------
    // Verification — forward full data to PKCS#11 using combined hash+verify mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Span entry-point — the .NET 10 BCL routes <c>VerifyData(ReadOnlySpan, ReadOnlySpan, …)</c>
    /// here.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is an unsupported signature padding, or <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown for a broken-hash signature (e.g. SHA-1) or a SHA-224 one (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(padding);
        var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Verify(mech, data, signature);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Byte-array entry-point — the .NET 10 BCL routes
    /// <c>VerifyData(byte[], byte[], …)</c> through here, NOT through the span overload.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/>, <paramref name="signature"/>, or <paramref name="padding"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/> is negative or outside the bounds of <paramref name="data"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is an unsupported signature padding, or <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown for a broken-hash signature (e.g. SHA-1) or a SHA-224 one (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        byte[] data,
        int offset,
        int count,
        byte[] signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(padding);
        if (offset < 0 || count < 0 || offset > data.Length - count)
            throw new ArgumentOutOfRangeException(nameof(offset));

        var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Verify(mech, data.AsSpan(offset, count), signature);
    }

    // -----------------------------------------------------------------------
    // Signing a digest — RSASSA-PKCS1-v1_5 over a DigestInfo, or CKM_RSA_PKCS_PSS
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Signs a digest the caller computed. PKCS#1 v1.5 is raw <c>CKM_RSA_PKCS</c> over the DER DigestInfo
    /// (RFC 8017 §9.2), which the session's policy judges as the combined mechanism for the hash
    /// (<c>CKM_SHA256_RSA_PKCS</c> for SHA-256): the verdict <c>SignData</c> gets for the same scheme. PSS is
    /// <c>CKM_RSA_PKCS_PSS</c> with the hash and a salt of its length in the parameters. The hash itself is
    /// put to the policy too. <see cref="RSA.TrySignHash"/> and the <see cref="Stream"/> overloads come here.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="hash"/> or <paramref name="padding"/> is <see langword="null"/>, or <paramref name="hashAlgorithm"/> has no name.</exception>
    /// <exception cref="CryptographicException"><paramref name="hash"/> is not the length of a <paramref name="hashAlgorithm"/> digest.</exception>
    /// <exception cref="NotSupportedException"><paramref name="padding"/> or <paramref name="hashAlgorithm"/> is not supported.</exception>
    /// <exception cref="CryptoPolicyViolationException">The session's policy refuses the hash or the mechanism.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ThrowIfNoHashName(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(padding);

        GuardHash(hashAlgorithm, CryptoOperation.Sign);
        if (hash.Length != DigestLength(hashAlgorithm))
            throw new CryptographicException($"The hash is {hash.Length} bytes; a {hashAlgorithm.Name} digest is {DigestLength(hashAlgorithm)}.");

        return padding == RSASignaturePadding.Pkcs1
            ? _key.SignPkcs1Digest(hashAlgorithm, hash)
            : _key.Sign(PssDigestMechanism(hashAlgorithm, padding), hash);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The counterpart of <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/>, under
    /// the same policy. A <paramref name="hash"/> of another length than the algorithm's digest does not
    /// verify. <see cref="RSA.VerifyHash(ReadOnlySpan{byte}, ReadOnlySpan{byte}, HashAlgorithmName, RSASignaturePadding)"/>
    /// and <see cref="RSA.VerifyData(Stream, byte[], HashAlgorithmName, RSASignaturePadding)"/> come here too.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="hash"/>, <paramref name="signature"/> or <paramref name="padding"/> is <see langword="null"/>, or <paramref name="hashAlgorithm"/> has no name.</exception>
    /// <exception cref="NotSupportedException"><paramref name="padding"/> or <paramref name="hashAlgorithm"/> is not supported.</exception>
    /// <exception cref="CryptoPolicyViolationException">The session's policy refuses the hash or the mechanism.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        ThrowIfNoHashName(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(padding);

        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        if (hash.Length != DigestLength(hashAlgorithm))
            return false;

        return padding == RSASignaturePadding.Pkcs1
            ? _key.VerifyPkcs1Digest(hashAlgorithm, hash, signature)
            : _key.Verify(PssDigestMechanism(hashAlgorithm, padding), hash, signature);
    }

    // Reached only by the non-virtual VerifyData(Stream, ...): the Stream signing overload above hashes
    // itself, so this can name the operation.
    /// <inheritdoc/>
    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        return base.HashData(data, hashAlgorithm);
    }

    // -----------------------------------------------------------------------
    // Encryption / decryption
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> or <paramref name="padding"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is neither PKCS#1 v1.5 nor OAEP, or the OAEP hash is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when <paramref name="padding"/> is PKCS#1 v1.5 (<c>CKM_RSA_PKCS</c>), or OAEP with a SHA-1 or SHA-224 hash, unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it; use OAEP with SHA-256 or stronger instead.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Encrypt</c> call.</exception>
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        var mech = EncryptMechanismFor(padding);
        return _key.Encrypt(mech, data);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <see cref="RSA.TryDecrypt"/> and both <see cref="RSA.Decrypt(ReadOnlySpan{byte}, RSAEncryptionPadding)"/>
    /// overloads come here. As for the BCL's own RSA, a ciphertext must be exactly the modulus's length, and its
    /// big-endian value must be less than the modulus; one that is not never reaches the token, which might
    /// otherwise answer it with a plaintext. <see cref="Pkcs11Key.Decrypt"/> checks it.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> or <paramref name="padding"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="padding"/> is neither PKCS#1 v1.5 nor OAEP, or the OAEP hash is not one of SHA-1/224/256/384/512 or SHA3-256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when <paramref name="padding"/> is PKCS#1 v1.5 (<c>CKM_RSA_PKCS</c>), or OAEP with a SHA-1 or SHA-224 hash, unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it; use OAEP with SHA-256 or stronger instead.</exception>
    /// <exception cref="CryptographicException">Thrown if <paramref name="data"/> is not the length of the key's modulus, or its value is not less than the modulus.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from reading the key's <c>CKA_MODULUS</c> or from the underlying <c>C_Decrypt</c> call.</exception>
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        var mech = EncryptMechanismFor(padding);
        return _key.Decrypt(mech, data);
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <see langword="true"/>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Thrown when the public material (<c>CKA_MODULUS</c> / <c>CKA_PUBLIC_EXPONENT</c>) is sensitive or cannot be read from any available handle.</exception>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptoPolicyViolationException(
                "Refusing to export RSA private parameters. PKCS#11 keys are non-extractable " +
                "by design; export only public material via ExportParameters(false).");

        return ToRSAParameters(_key.Export(Pkcs11KeyBlobFormat.RawPublicKey));
    }

    // Parses the PKCS#1 RSAPublicKey Pkcs11Key.Export writes. Not through RSA.ImportRSAPublicKey: that
    // creates a platform key for a read that needs none. A DER INTEGER is two's complement, so a modulus
    // whose top bit is set carries one leading 0x00 byte, which RSAParameters does not want.
    private static RSAParameters ToRSAParameters(byte[] rsaPublicKey)
    {
        try
        {
            AsnReader sequence = new AsnReader(rsaPublicKey, AsnEncodingRules.DER).ReadSequence();
            return new RSAParameters
            {
                Modulus = Unsigned(sequence.ReadIntegerBytes()),
                Exponent = Unsigned(sequence.ReadIntegerBytes()),
            };
        }
        catch (AsnContentException ex)
        {
            // Pkcs11Key.Export writes this encoding itself, so reaching here is a library bug.
            throw new CryptographicException("Pkcs11Key.Export returned a malformed RSAPublicKey.", ex);
        }
    }

    private static byte[] Unsigned(ReadOnlyMemory<byte> integer)
        => (integer.Span is [0x00, _, ..] ? integer[1..] : integer).ToArray();

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(RSAParameters parameters)
        => throw new NotSupportedException(
            "RSAPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Session.ImportKey or GenerateKey instead.");

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Maps a BCL hash + signature padding to a PKCS#11 mechanism that hashes and signs
    /// in one shot on the token. This avoids using the insecure-by-default
    /// <c>CKM_RSA_PKCS</c> raw-sign mechanism.
    /// </summary>
    private static Mechanism SignMechanismFor(HashAlgorithmName hash, RSASignaturePadding padding)
    {
        // Policy (see the session's crypto policy check and the README "Security model" section):
        // strong-hash (SHA-2/SHA-3) RSASSA-PKCS1-v1_5 *signatures* are allowed by default. The
        // policy gate targets broken *hashes* (MD2/MD5/SHA-1/RIPEMD — rejected in every
        // context, RsaPkcs1Sign won't map them) and PKCS#1 v1.5 *encryption* / raw RSA, not v1.5
        // signing with a strong hash. The latter remains FIPS 186-5-approved and is mandated by
        // ubiquitous interop (JWT RS256, TLS 1.2 CertificateVerify, X.509, code signing). Prefer
        // PSS for new code, but do not require an insecure opt-in for a secure, standard scheme.
        if (padding == RSASignaturePadding.Pkcs1)
            return Pkcs11MechanismMap.RsaPkcs1Sign(hash);
        if (padding.Mode == RSASignaturePaddingMode.Pss)
            return Pkcs11MechanismMap.RsaPssSign(hash, saltLength: -1);
        throw new NotSupportedException($"Unsupported RSA signature padding: {padding}.");
    }

    // As the BCL: a missing name is an ArgumentNullException and an empty one an ArgumentException, both
    // naming hashAlgorithm rather than its Name.
    private static void ThrowIfNoHashName(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm.Name is null)
            throw new ArgumentNullException(nameof(hashAlgorithm));
        if (hashAlgorithm.Name.Length == 0)
            throw new ArgumentException("The value cannot be an empty string.", nameof(hashAlgorithm));
    }

    // The combined mechanisms carry the hash, so the policy judges it there; a digest the caller computed
    // reaches the token through a raw mechanism, so the hash is put to the policy on its own.
    private void GuardHash(HashAlgorithmName hashAlgorithm, CryptoOperation operation)
        => _key.Session.Enforce(new HashUseRequest(hashAlgorithm, operation));

    private static int DigestLength(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => 20,
        "SHA224" => 28,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        "SHA3-256" => 32,
        "SHA3-384" => 48,
        "SHA3-512" => 64,
        _ => throw new NotSupportedException($"RSA does not support hash {hash.Name}."),
    };

    // CKM_RSA_PKCS_PSS over a digest, with the parameters the combined PSS mechanism would carry: the
    // hash, its MGF1, and a salt of the hash's length, as the BCL's Pss uses.
    private static Mechanism PssDigestMechanism(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        => padding.Mode == RSASignaturePaddingMode.Pss
            ? new Mechanism(CKM.CKM_RSA_PKCS_PSS, Pkcs11MechanismMap.RsaPssSign(hashAlgorithm, saltLength: -1).Parameters!)
            : throw new NotSupportedException($"Unsupported RSA signature padding: {padding}.");

    private static Mechanism EncryptMechanismFor(RSAEncryptionPadding padding)
    {
        // CKM_RSA_PKCS is gated by the session's crypto policy check — Encrypt/Decrypt will throw
        // CryptoPolicyViolationException unless the caller's policy permits it. This is the
        // mapper that hands the mechanism to that gate, so KLPKCS11008 (which exists to warn a
        // *caller* who selects v1.5 padding) fires on the wrong side of the check here.
#pragma warning disable KLPKCS11008 // the runtime gate below is the enforcement point
        if (padding == RSAEncryptionPadding.Pkcs1)
            return new Mechanism(CKM.CKM_RSA_PKCS);
#pragma warning restore KLPKCS11008
        if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            return Pkcs11MechanismMap.RsaOaep(padding.OaepHashAlgorithm);
        throw new NotSupportedException($"Unsupported RSA encryption padding: {padding}.");
    }
}
