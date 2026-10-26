using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

// This file builds the very mechanisms the secure-by-default policy gates: it sits on the
// enforcement side of the check (the session's crypto policy check rejects them at the point of
// use unless the session's crypto policy permits it), whereas KLPKCS11009 exists to warn a *caller* who selects one.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned ECDsa provider backed by a PKCS#11 <c>Pkcs11Key</c>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="ECDsa"/> so callers can pass this instance anywhere a BCL
/// <c>ECDsa</c> is accepted (e.g. <c>ECDsaCertificateExtensions</c>, ASP.NET Core signing).
/// </para>
/// <para>
/// Only the span overloads (<c>TrySignData</c>, <c>VerifyData(ReadOnlySpan, ReadOnlySpan, ...)</c>),
/// which this class overrides directly, forward the full un-hashed data to PKCS#11 for on-token
/// hashing + signing/verification via the combined mechanism (e.g. <c>CKM_ECDSA_SHA256</c>). The
/// <c>byte[]</c> convenience overloads (<c>SignData(byte[], HashAlgorithmName)</c>, virtual but not
/// overridden here, and the non-virtual <c>VerifyData(byte[], byte[], HashAlgorithmName)</c>) do NOT
/// dispatch through them — verified
/// empirically, not assumed: the BCL's own <see cref="ECDsa"/> base-class implementation pre-hashes
/// via the protected <c>HashData</c> override below, then signs/verifies that hash directly through
/// <c>SignHash</c>/<c>VerifyHash</c> (raw <c>CKM_ECDSA</c>, no combined mechanism). One consequence:
/// a hash algorithm the BCL cannot compute itself (e.g. SHA-224, which has no
/// <see cref="HashAlgorithmName"/> constant) throws inside the BCL's own pre-hash step before this
/// class's code ever runs, on every backend — see <c>ECDsaPkcs11TestCases</c>'s SHA-224 coverage,
/// which exercises only the span path for this reason.
/// </para>
/// <para>
/// Signature sizes come from the library's <see cref="Pkcs11LibraryOptions.CurveCatalog"/>.
/// <see cref="AsymmetricAlgorithm.KeySize"/> is the curve's field size, as the BCL reports it. The r‖s
/// (IEEE P1363) form is the token's: r and s each take the length of the group order n, as PKCS#11 defines
/// them. On secp160k1, secp160r1, secp160r2 and secp224k1, n is one bit longer than the field, so an r‖s
/// signature is two bytes longer than the BCL's own for the curve, and than
/// <see cref="ECDsa.GetMaxSignatureSize(DSASignatureFormat)"/>, which is not virtual and sizes from
/// <c>KeySize</c>. The DER form is the same on both sides.
/// </para>
/// <para>
/// On a curve the catalog doesn't list, <c>KeySize</c> stays 0 and a DER signature can't be converted
/// for the token, so it does not verify; describe the curve with <see cref="Pkcs11CurveCatalog.With(Pkcs11CurveInfo)"/>.
/// </para>
/// </remarks>
public sealed class ECDsaPkcs11 : ECDsa
{
    private readonly Pkcs11Key _key;

    // The length of r and of s in the token's r‖s signature, (order bits + 7) / 8; 0 for a curve the
    // library's catalog doesn't list.
    private readonly int _signatureFieldSize;

    /// <summary>
    /// Wraps a PKCS#11 EC key as a BCL <see cref="ECDsa"/> instance. Does not take
    /// ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_EC"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an EC key.</exception>
    public ECDsaPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_EC)
            throw new ArgumentException(
                $"Expected an EC key, got {key.KeyType}.", nameof(key));
        _key = key;

        // Reflect the token key's real curve: KeySize is its field size, and r and s are each as long as
        // its group order. Best-effort: the ECDsa base constructor leaves KeySize=0 (via KeySizeValue),
        // which we keep if the curve can't be identified. Neither size can be derived from the key itself:
        // CKA_EC_PARAMS is only the curve's OID, and CKA_EC_POINT gives the field's byte length, which the
        // order's can exceed by one (secp224k1).
        if (AsymmetricKeySize.TryReadEcCurve(key) is { } curve)
        {
            KeySizeValue = curve.FieldSizeBits;
            LegalKeySizesValue = AsymmetricKeySize.Only(curve.FieldSizeBits);
            _signatureFieldSize = (curve.OrderSizeBits + 7) / 8;
        }
    }

    // -----------------------------------------------------------------------
    // Signing — forward full data to PKCS#11 using combined hash+sign mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// The virtual span entry-point: callers who invoke this directly (or through
    /// <c>TrySignData(ReadOnlySpan, ...)</c> generically) get the complete, un-hashed data forwarded
    /// to PKCS#11, which hashes on-token (e.g. <c>CKM_ECDSA_SHA256</c> for SHA-256). The BCL's
    /// <c>SignData(byte[], HashAlgorithmName)</c> convenience overload, which this class does not
    /// override, does NOT reach this method — see the class remarks.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512, or is SHA-224 on a token with neither <c>CKM_ECDSA_SHA224</c> nor the <c>CKM_SHA224</c> digest.</exception>
    /// <exception cref="PlatformNotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is SHA-3, the token lacks the combined <c>CKM_ECDSA_SHA3_*</c> mechanism, and the platform has no SHA-3.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when <paramref name="hashAlgorithm"/> is SHA-1 (broken) or SHA-224 (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override bool TrySignData(
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        HashAlgorithmName hashAlgorithm,
        out int bytesWritten)
    {
        byte[] sig = SignDataInternal(data, hashAlgorithm);
        if (sig.Length > destination.Length) { bytesWritten = 0; return false; }
        sig.CopyTo(destination);
        bytesWritten = sig.Length;
        return true;
    }

    // -----------------------------------------------------------------------
    // Verification — forward full data to PKCS#11 using combined hash+verify mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// The virtual span entry-point: callers who invoke this directly get the complete, un-hashed
    /// data forwarded to PKCS#11. The BCL's non-virtual
    /// <see cref="ECDsa.VerifyData(byte[], byte[], HashAlgorithmName)"/> convenience overload does NOT
    /// reach this method — see the class remarks.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512 or SHA3-256/384/512, or is SHA-224 on a token with neither <c>CKM_ECDSA_SHA224</c> nor the <c>CKM_SHA224</c> digest.</exception>
    /// <exception cref="PlatformNotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is SHA-3, the token lacks the combined <c>CKM_ECDSA_SHA3_*</c> mechanism, and the platform has no SHA-3.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when <paramref name="hashAlgorithm"/> is SHA-1 (broken) or SHA-224 (no BCL constant, no benefit over SHA-256) unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (_key.SupportsMechanism(combined.Type))
        {
            return HasSignatureLength(signature) && _key.Verify(combined, data, signature);
        }
        byte[] hash = HashData(hashAlgorithm, data, CryptoOperation.Verify);
        var raw = new Mechanism(CKM.CKM_ECDSA);
        return HasSignatureLength(signature) && _key.Verify(raw, hash, signature);
    }

    // The BCL routes these verification overloads through the protected HashData overrides, which are
    // shared with SignData and cannot tell which direction called them. Overriding them here lets the
    // pre-hash report CryptoOperation.Verify, so a direction-sensitive policy (FipsOnly allows SHA-1
    // only for legacy verification) sees the same verdict whichever overload the caller picks. The
    // hashing and the digest verification are otherwise exactly what the base class does.

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's session's <see cref="Pkcs11Session.Policy"/> refuses <paramref name="hashAlgorithm"/> for verification.</exception>
    public override bool VerifyData(byte[] data, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, data.Length);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, data.Length - offset);
        ArgumentNullException.ThrowIfNull(signature);
        if (string.IsNullOrEmpty(hashAlgorithm.Name))
            throw new ArgumentException("Hash algorithm must be specified.", nameof(hashAlgorithm));

        GuardWeakHash(hashAlgorithm, CryptoOperation.Verify);
        return VerifyHash(base.HashData(data, offset, count, hashAlgorithm), signature);
    }

    /// <inheritdoc/>
    /// <remarks>Also reached by the non-virtual <c>VerifyData(Stream, byte[], HashAlgorithmName)</c>.</remarks>
    protected override bool VerifyDataCore(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        DSASignatureFormat signatureFormat)
    {
        GuardWeakHash(hashAlgorithm, CryptoOperation.Verify);
        byte[] buffer = data.ToArray();
        return VerifyHashCore(base.HashData(buffer, 0, buffer.Length, hashAlgorithm), signature, signatureFormat);
    }

    /// <inheritdoc/>
    protected override bool VerifyDataCore(
        Stream data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        DSASignatureFormat signatureFormat)
    {
        GuardWeakHash(hashAlgorithm, CryptoOperation.Verify);
        return VerifyHashCore(base.HashData(data, hashAlgorithm), signature, signatureFormat);
    }

    // The Stream signing overloads hash here, with Sign, so that the protected HashData(Stream) override
    // below is reached only by the non-virtual VerifyData(Stream, byte[], HashAlgorithmName), which
    // cannot be overridden and goes straight to it — that override can then report Verify.

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's session's <see cref="Pkcs11Session.Policy"/> refuses <paramref name="hashAlgorithm"/> for signing.</exception>
    public override byte[] SignData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (string.IsNullOrEmpty(hashAlgorithm.Name))
            throw new ArgumentException("Hash algorithm must be specified.", nameof(hashAlgorithm));

        GuardWeakHash(hashAlgorithm, CryptoOperation.Sign);
        return SignHash(base.HashData(data, hashAlgorithm));
    }

    /// <inheritdoc/>
    protected override byte[] SignDataCore(Stream data, HashAlgorithmName hashAlgorithm, DSASignatureFormat signatureFormat)
    {
        GuardWeakHash(hashAlgorithm, CryptoOperation.Sign);
        return SignHashCore(base.HashData(data, hashAlgorithm), signatureFormat);
    }

    // -----------------------------------------------------------------------
    // Sign/verify hash — raw ECDSA (no on-token hashing)
    // The BCL declares the byte-array SignHash and VerifyHash overloads abstract, so
    // they must be implemented directly here.
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Signs the caller-supplied digest with raw <c>CKM_ECDSA</c>. The hash algorithm is not
    /// conveyed on this path, so the SHA-1 secure-defaults gate does not apply here.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="hash"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(mech, hash);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="hash"/> or <paramref name="signature"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        var mech = new Mechanism(CKM.CKM_ECDSA);
        return HasSignatureLength(signature) && _key.Verify(mech, hash, signature);
    }

    // An IEEE P1363 signature is r || s, each as long as the curve's group order (PKCS#11's r and s): any
    // other length is invalid, and the BCL's ECDsa returns false for it. The order's length, not KeySize:
    // on secp160k1, secp160r1, secp160r2 and secp224k1 the order is one bit longer than the field, and a
    // valid r || s two bytes longer than twice the field's size. Checked here because modules report it
    // inconsistently: SoftHSM2 and Kryoptic with CKR_SIGNATURE_LEN_RANGE, NSS 3.51 with CKR_DATA_LEN_RANGE.
    // On a curve the catalog doesn't list (size 0) the module decides.
    private bool HasSignatureLength(ReadOnlySpan<byte> signature)
        => _signatureFieldSize == 0 || signature.Length == 2 * _signatureFieldSize;

    // Every verification with a DSASignatureFormat ends here. The base class converts a DER signature to
    // r‖s sized from KeySize, the field size, which is one byte short of r and s on a curve whose order is
    // longer than its field; on a curve the catalog doesn't list it sizes to zero, and a zero r or s then
    // threw IndexOutOfRangeException. This sizes from the order instead.

    /// <inheritdoc/>
    /// <remarks>
    /// A DER signature is converted to r‖s with r and s each as long as the curve's group order, the form
    /// the token verifies. One that is malformed, has a value too long for the curve, or is on a curve the
    /// library's catalog doesn't list does not verify, as for the BCL's own conversion.
    /// </remarks>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    protected override bool VerifyHashCore(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        DSASignatureFormat signatureFormat)
    {
        if (signatureFormat != DSASignatureFormat.Rfc3279DerSequence)
            return base.VerifyHashCore(hash, signature, signatureFormat);

        byte[]? ieee = _signatureFieldSize == 0 ? null : DssSignatureEncoding.DerToIeeeP1363(signature, _signatureFieldSize);
        return ieee is not null && VerifyHash(hash.ToArray(), ieee);
    }

    private byte[] SignDataInternal(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (_key.SupportsMechanism(combined.Type))
            return _key.Sign(combined, data);
        byte[] hash = HashData(hashAlgorithm, data, CryptoOperation.Sign);
        var raw = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(raw, hash);
    }

    // Submits the hash choice to the wrapped key's session policy, mirroring SecureOnlyPolicy's
    // rejection of the combined CKM_ECDSA_SHA1 mechanism. Gating here (the managed-side pre-hash)
    // closes the gap for tokens that lack the combined mechanism. Every entry point that knows the hash
    // algorithm is gated with its own direction: the verification overloads above hash with Verify, the
    // span overloads through the private hasher, the byte[] HashData override (reached only by the
    // signing overloads) with Sign, and the Stream HashData override (reached only by the non-virtual
    // Stream verification overload) with Verify. SignHash / VerifyHash(byte[]) take
    // caller-supplied digest bytes and cannot know the algorithm, so they are outside this gate.
    private void GuardWeakHash(HashAlgorithmName hashAlgorithm, CryptoOperation operation)
        => _key.Session.Enforce(new HashUseRequest(hashAlgorithm, operation));

    /// <inheritdoc/>
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        GuardWeakHash(hashAlgorithm, CryptoOperation.Sign);
        return base.HashData(data, offset, count, hashAlgorithm);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Reached only by the non-virtual <c>VerifyData(Stream, byte[], HashAlgorithmName)</c>: the Stream
    /// signing overloads and <c>VerifyDataCore(Stream, …)</c> are overridden above and hash without
    /// coming here, so the hash choice is reported as a verification.
    /// </remarks>
    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        GuardWeakHash(hashAlgorithm, CryptoOperation.Verify);
        return base.HashData(data, hashAlgorithm);
    }

    // The span overloads' hasher, for a token without the combined CKM_ECDSA_* mechanism. SHA-3 is the
    // BCL's, which throws PlatformNotSupportedException where the platform has no SHA-3, as the BCL's own
    // ECDsa does. .NET has no SHA-224 through any API, so a SHA-224 digest is the token's CKM_SHA224; a
    // token with neither falls through to the NotSupportedException below rather than to a hand-rolled
    // SHA-224 that this adapter has no business owning.
    private byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data, CryptoOperation operation)
    {
        GuardWeakHash(hashAlgorithm, operation);
        return hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.HashData(data),
            "SHA224" when _key.SupportsMechanism(CKM.CKM_SHA224, CKF.CKF_DIGEST) => _key.Session.Digest(new Mechanism(CKM.CKM_SHA224), data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            "SHA3-256" => SHA3_256.HashData(data),
            "SHA3-384" => SHA3_384.HashData(data),
            "SHA3-512" => SHA3_512.HashData(data),
            _ => throw new NotSupportedException($"ECDSA does not support hash {hashAlgorithm.Name}.")
        };
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <see langword="true"/>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) is sensitive, cannot be read from any available handle, or cannot be parsed as a named-curve uncompressed point.</exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptoPolicyViolationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        return EcSubjectPublicKeyInfo.ToECParameters(_key);
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        => throw new NotSupportedException(
            "Explicit (non-named-curve) parameter export is not supported. " +
            "Use ExportParameters(false) for named-curve parameters.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(ECParameters parameters)
        => throw new NotSupportedException(
            "ECDsaPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Session.ImportKey or GenerateKey instead.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException(
            "Use Pkcs11Session.GenerateKey to generate keys on the token.");
}
