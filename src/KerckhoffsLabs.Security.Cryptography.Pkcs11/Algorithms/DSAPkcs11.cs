using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

// This file builds the very mechanisms the secure-by-default policy gates: it sits on the
// enforcement side of the check (the session's crypto policy check rejects them at the point of
// use unless the session's crypto policy permits it), whereas KLPKCS11009 exists to warn a *caller* who selects one.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned DSA provider backed by a PKCS#11 <see cref="Pkcs11Key"/>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="DSA"/> so callers can pass this instance anywhere a BCL <c>DSA</c> is
/// accepted. Signing forwards the full message to the combined <c>CKM_DSA_SHA*</c> mechanism so the
/// token hashes and signs in one <c>C_Sign</c> call; if the token lacks the combined mechanism it
/// falls back to hashing on the managed side and signing the digest with raw <c>CKM_DSA</c>. Both
/// produce IEEE P1363 (r‖s) signatures, matching the BCL default — the base class converts to the
/// DER format on request via the <c>DSASignatureFormat</c> overloads. Verification with a
/// <c>DSASignatureFormat</c> converts a DER signature to r‖s here, sizing it from the key's
/// <c>CKA_SUBPRIME</c>, and verifies it with raw <c>CKM_DSA</c>.
/// </para>
/// <para>
/// Note: NIST FIPS 186-5 (2023) disallows DSA for signature generation; this adapter is for interop
/// with existing DSA keys. Private-key parameter export is refused (PKCS#11 keys are non-extractable);
/// <see cref="ExportParameters(bool)"/> with <see langword="false"/> reads the domain parameters and public value
/// (<c>CKA_PRIME</c> / <c>CKA_SUBPRIME</c> / <c>CKA_BASE</c> / <c>CKA_VALUE</c>) from the public handle.
/// </para>
/// <para>
/// <see cref="DSA.GetMaxSignatureSize(DSASignatureFormat)"/> is not virtual and reads q through
/// <see cref="ExportParameters(bool)"/>, so like it, it needs the key's public-key object: on a key
/// with only a private-key object it throws <see cref="Pkcs11Exception"/>
/// (<see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/>), although that key can sign. The public value Y is not
/// on the private-key object, whose <c>CKA_VALUE</c> is the private value, and <c>DSAParameters</c>
/// without Y is not a public key. Verification needs that object too, and on such a key every verify
/// overload throws the same error, whatever the signature's length or encoding.
/// </para>
/// </remarks>
[Obsolete("DSA is disallowed for signature generation by NIST FIPS 186-5 (2023) and is removed from modern " +
          "deployments. Use ECDsaPkcs11 (ECDSA) or MLDsaPkcs11 (ML-DSA). DSAPkcs11 remains only for interop " +
          "with existing DSA keys; SHA-1 hashing additionally requires a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) on the wrapped key's session.",
    DiagnosticId = DiagnosticIds.Dsa,
    UrlFormat = DiagnosticIds.UrlFormat)]
public sealed class DSAPkcs11 : DSA
{
    private readonly Pkcs11Key _key;

    // q's length in bytes, read from the token on first use; 0 until then, which no key's q is. A plain int,
    // so a thread that reads it while another first writes it sees either 0 or the whole length.
    private int _subprimeLength;

    /// <summary>
    /// Wraps a PKCS#11 DSA key as a BCL <see cref="DSA"/> instance. Does not take ownership —
    /// disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is <see cref="CKK.CKK_DSA"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not a DSA key.</exception>
    public DSAPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_DSA)
            throw new ArgumentException($"Expected a DSA key, got {key.KeyType}.", nameof(key));
        _key = key;

        // Reflect the token key's real prime-modulus size. Best-effort: the DSA base constructor
        // leaves KeySize=0 (via KeySizeValue), which we keep if the token doesn't expose CKA_PRIME —
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
            // C_GetAttributeValue failed — leave KeySize at the DSA base-class default.
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // Sign / verify a hash — raw CKM_DSA (P1363 r‖s)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rgbHash"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it: every <c>CKM_DSA</c> mechanism is gated because FIPS 186-5 disallows DSA signature generation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] CreateSignature(byte[] rgbHash)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);
        var mech = new Mechanism(CKM.CKM_DSA);
        return _key.Sign(mech, rgbHash);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rgbHash"/> or <paramref name="rgbSignature"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown when <c>CKA_SUBPRIME</c> cannot be read to check the signature's length.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key has no public-key object; <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when <c>CKA_SUBPRIME</c> is zero; otherwise propagated from reading it or from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);
        ArgumentNullException.ThrowIfNull(rgbSignature);
        var mech = new Mechanism(CKM.CKM_DSA);
        return VerifyIeeeP1363(mech, rgbHash, rgbSignature);
    }

    // Every verification with a DSASignatureFormat ends here. The base class sizes q through
    // ExportParameters(false) inside a catch of CryptographicException, which would turn a token error
    // (Pkcs11Exception) into false without ever reaching C_Verify; this reads q's length from CKA_SUBPRIME
    // and lets the token's errors through.

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown when <c>CKA_SUBPRIME</c> cannot be read to size the signature.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key has no public-key object; <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when <c>CKA_SUBPRIME</c> is zero; otherwise propagated from reading it or from the underlying <c>C_Verify</c> call.</exception>
    protected override bool VerifySignatureCore(
        ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, DSASignatureFormat signatureFormat)
    {
        var mech = new Mechanism(CKM.CKM_DSA);
        switch (signatureFormat)
        {
            case DSASignatureFormat.IeeeP1363FixedFieldConcatenation:
                return VerifyIeeeP1363(mech, hash, signature);
            case DSASignatureFormat.Rfc3279DerSequence:
                // A malformed signature does not verify, as for the BCL's own conversion.
                EnsureCanVerify(mech);
                byte[]? ieee = DerToIeeeP1363(signature, GetSubprimeLength());
                return ieee is not null && _key.Verify(mech, hash, ieee);
            default:
                // The public overloads reject an unknown format before reaching here; as DSAOpenSsl.
                throw new CryptographicException($"Unknown signature format '{signatureFormat}'.");
        }
    }

    // An r‖s signature is twice q's length, and one of another length does not verify, as for the BCL's own
    // DSA. It is not passed to the token, which may not say so: NSS answers it with CKR_ARGUMENTS_BAD rather
    // than a verdict, which the session core rightly does not take as one.
    private bool VerifyIeeeP1363(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        EnsureCanVerify(mechanism);
        return signature.Length == 2 * GetSubprimeLength() && _key.Verify(mechanism, data, signature);
    }

    // Before the signature is looked at, the two things that make a verification fail regardless of it. The
    // session's policy is asked first, as the token path asks it, so a refused mechanism is refused before
    // the token is read. Then the public-key object: without it the key cannot verify (Pkcs11Key has no
    // managed DSA fallback), and saying so here keeps a signature's length or encoding from choosing between
    // that error and false.
    private void EnsureCanVerify(Mechanism mechanism)
    {
        _key.Session.Enforce(new MechanismUseRequest(mechanism, CryptoOperation.Verify));
        if (!_key.HasPublicKeyObject)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "DSAPkcs11 verify (no public-key object)");
    }

    // q's length in bytes, as ExportParameters(false) reports it, but from CKA_SUBPRIME alone, without the
    // public value ExportParameters also reads. Read once: a key object's domain parameters cannot be modified.
    private int GetSubprimeLength()
    {
        int length = Volatile.Read(ref _subprimeLength);
        if (length != 0)
            return length;

        using var subprime = _key.GetAttributeValue(CKA.CKA_SUBPRIME);
        // CannotBeRead covers both a sensitive attribute and one the object lacks, so no return code is named.
        if (subprime[0].CannotBeRead)
            throw new Pkcs11AttributeException(CKA.CKA_SUBPRIME);
        byte[] q = TrimLeadingZeros(subprime[0].GetValueAsByteArray());
        if (q is [] or [0])
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID, "DSAPkcs11 (CKA_SUBPRIME is zero)");
        Volatile.Write(ref _subprimeLength, q.Length);
        return q.Length;
    }

    // RFC 3279 Dss-Sig-Value { r, s } to r‖s, each left-padded to fieldLength; null when the encoding is
    // malformed or a value does not fit, where the BCL's conversion throws and its caller returns false.
    private static byte[]? DerToIeeeP1363(ReadOnlySpan<byte> signature, int fieldLength)
    {
        try
        {
            AsnDecoder.ReadSequence(signature, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
            if (consumed != signature.Length)
                return null;
            ReadOnlySpan<byte> sequence = signature.Slice(offset, length);
            ReadOnlySpan<byte> r = AsnDecoder.ReadIntegerBytes(sequence, AsnEncodingRules.DER, out consumed);
            sequence = sequence[consumed..];
            ReadOnlySpan<byte> s = AsnDecoder.ReadIntegerBytes(sequence, AsnEncodingRules.DER, out consumed);
            if (consumed != sequence.Length)
                return null;

            byte[] ieee = new byte[2 * fieldLength];
            return TryCopyField(r, ieee.AsSpan(0, fieldLength)) && TryCopyField(s, ieee.AsSpan(fieldLength))
                ? ieee
                : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    // A DER INTEGER is one byte longer than the field only for the zero that keeps a set high bit positive.
    private static bool TryCopyField(ReadOnlySpan<byte> field, Span<byte> destination)
    {
        if (field.Length > destination.Length)
        {
            if (field.Length != destination.Length + 1 || field is not [0, > 0x7F, ..])
                return false;
            field = field[1..];
        }
        field.CopyTo(destination[(destination.Length - field.Length)..]);
        return true;
    }

    // -----------------------------------------------------------------------
    // Sign / verify data — combined on-token hash+sign (CKM_DSA_SHA*)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override bool TrySignData(
        ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten)
    {
        byte[] sig = SignDataInternal(data, hashAlgorithm);
        if (sig.Length > destination.Length) { bytesWritten = 0; return false; }
        sig.CopyTo(destination);
        bytesWritten = sig.Length;
        return true;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits it: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown when <c>CKA_SUBPRIME</c> cannot be read to check the signature's length.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key has no public-key object; <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when <c>CKA_SUBPRIME</c> is zero; otherwise propagated from reading it or from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.DsaSign(hashAlgorithm);
        if (_key.SupportsMechanism(combined.Type))
            return VerifyIeeeP1363(combined, data, signature);

        byte[] hash = HashData(hashAlgorithm, data, CryptoOperation.Verify);
        var raw = new Mechanism(CKM.CKM_DSA);
        return VerifyIeeeP1363(raw, hash, signature);
    }

    // The BCL routes these verification overloads through the protected HashData overrides, which are
    // shared with the signing ones and cannot tell which direction called them. Overriding them here lets
    // the hash be judged as a verification. The hashing and the digest verification are otherwise
    // exactly what the base class does.

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits <paramref name="hashAlgorithm"/> and <c>CKM_DSA</c> for verification.</exception>
    public override bool VerifyData(byte[] data, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, data.Length);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, data.Length - offset);
        ArgumentNullException.ThrowIfNull(signature);
        ThrowIfNoHashName(hashAlgorithm);

        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        return VerifySignature(base.HashData(data, offset, count, hashAlgorithm), signature);
    }

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Thrown unless the wrapped key's session's <see cref="Pkcs11Session.Policy"/> permits <paramref name="hashAlgorithm"/> and <c>CKM_DSA</c> for verification.</exception>
    public override bool VerifyData(Stream data, byte[] signature, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ThrowIfNoHashName(hashAlgorithm);

        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        return VerifySignature(base.HashData(data, hashAlgorithm), signature);
    }

    /// <inheritdoc/>
    protected override bool VerifyDataCore(
        ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, DSASignatureFormat signatureFormat)
    {
        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        byte[] buffer = data.ToArray();
        return VerifySignatureCore(base.HashData(buffer, 0, buffer.Length, hashAlgorithm), signature, signatureFormat);
    }

    /// <inheritdoc/>
    protected override bool VerifyDataCore(
        Stream data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, DSASignatureFormat signatureFormat)
    {
        GuardHash(hashAlgorithm, CryptoOperation.Verify);
        return VerifySignatureCore(base.HashData(data, hashAlgorithm), signature, signatureFormat);
    }

    // With every verification overload above hashing on its own, the base class reaches these two only
    // from its signing overloads (SignData, TrySignData and SignDataCore, with or without a format).

    /// <inheritdoc/>
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        GuardHash(hashAlgorithm, CryptoOperation.Sign);
        return base.HashData(data, offset, count, hashAlgorithm);
    }

    /// <inheritdoc/>
    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        GuardHash(hashAlgorithm, CryptoOperation.Sign);
        return base.HashData(data, hashAlgorithm);
    }

    private byte[] SignDataInternal(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.DsaSign(hashAlgorithm);
        if (_key.SupportsMechanism(combined.Type))
            return _key.Sign(combined, data);

        byte[] hash = HashData(hashAlgorithm, data, CryptoOperation.Sign);
        var raw = new Mechanism(CKM.CKM_DSA);
        return _key.Sign(raw, hash);
    }

    // Every path that hashes on the managed side puts the hash to the session's policy, in the direction
    // of the operation: a combined CKM_DSA_SHA* mechanism carries its hash to the policy, but raw CKM_DSA
    // over a managed digest does not, and a policy may permit CKM_DSA yet refuse a hash (SHA-1). The
    // built-in policies already refuse or allow the two together; a custom one need not.
    // CreateSignature and VerifySignature take a caller's digest and cannot know the hash, so they are
    // outside this check, as ECDsaPkcs11's SignHash and VerifyHash are.
    private void GuardHash(HashAlgorithmName hashAlgorithm, CryptoOperation operation)
        => _key.Session.Enforce(new HashUseRequest(hashAlgorithm, operation));

    // As the BCL: a missing name is an ArgumentNullException and an empty one an ArgumentException, both
    // naming hashAlgorithm rather than its Name.
    private static void ThrowIfNoHashName(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm.Name is null)
            throw new ArgumentNullException(nameof(hashAlgorithm));
        if (hashAlgorithm.Name.Length == 0)
            throw new ArgumentException("The value cannot be an empty string.", nameof(hashAlgorithm));
    }

    //
    // SHA-224 is deliberately absent: Pkcs11MechanismMap.DsaSign accepts it (CKM_DSA_SHA224 is a real
    // PKCS#11 mechanism), but .NET has no SHA-224 implementation through any API — no concrete type,
    // and IncrementalHash.CreateHash(new HashAlgorithmName("SHA224")) throws CryptographicException
    // ("not a known hash algorithm"). If the token doesn't support the combined CKM_DSA_SHA224
    // mechanism itself, this managed-side fallback has no way to compute the hash, so SHA-224 falls
    // through to the NotSupportedException below rather than a hand-rolled SHA-224 (same compression
    // function as SHA-256, different IV, truncated output) that this adapter has no business owning.
    private byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data, CryptoOperation operation)
    {
        GuardHash(hashAlgorithm, operation);
        return hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.HashData(data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"DSA does not support hash {hashAlgorithm.Name}."),
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
    /// <exception cref="Pkcs11Exception">Thrown when the domain parameters or public value (<c>CKA_PRIME</c> / <c>CKA_SUBPRIME</c> / <c>CKA_BASE</c> / <c>CKA_VALUE</c>) are sensitive or cannot be read, or the key has no public-key object to read <c>CKA_VALUE</c> from.</exception>
    public override DSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptoPolicyViolationException(
                "Refusing to export DSA private key (X). PKCS#11 keys are non-extractable by design; " +
                "export only public material via ExportParameters(false).");

        // Y is read from the public-key object only; see Pkcs11Key.Export.
        return ToDSAParameters(_key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
    }

    // Parses the RFC 3279 SubjectPublicKeyInfo Pkcs11Key.Export writes: Dss-Parms { p, q, g } and
    // INTEGER y. Not through DSA.ImportSubjectPublicKeyInfo: macOS's BCL cannot hold every DSA key.
    private static DSAParameters ToDSAParameters(byte[] spki)
    {
        try
        {
            AsnReader info = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
            AsnReader algorithm = info.ReadSequence();
            algorithm.ReadObjectIdentifier();
            AsnReader domain = algorithm.ReadSequence();
            byte[] p = TrimLeadingZeros(domain.ReadIntegerBytes().ToArray());
            byte[] q = TrimLeadingZeros(domain.ReadIntegerBytes().ToArray());
            byte[] g = domain.ReadIntegerBytes().ToArray();
            byte[] y = new AsnReader(info.ReadBitString(out _), AsnEncodingRules.DER).ReadIntegerBytes().ToArray();
            return new DSAParameters
            {
                P = p,
                Q = q,
                // DSAParameters requires G and Y to share the prime length; left-pad to P.
                G = LeftPad(g, p.Length),
                Y = LeftPad(y, p.Length),
            };
        }
        catch (AsnContentException ex)
        {
            // Pkcs11Key.Export writes this encoding itself, so reaching here is a library bug.
            throw new CryptographicException("Pkcs11Key.Export returned a malformed DSA SubjectPublicKeyInfo.", ex);
        }
    }

    private static byte[] TrimLeadingZeros(byte[] value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0) start++;
        return start == 0 ? value : value[start..];
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        value = TrimLeadingZeros(value);
        if (value.Length == length) return value;
        if (value.Length > length) return value[^length..];
        byte[] result = new byte[length];
        value.CopyTo(result, length - value.Length);
        return result;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(DSAParameters parameters)
        => throw new NotSupportedException(
            "DSAPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Session.ImportKey or GenerateKey instead.");
}
