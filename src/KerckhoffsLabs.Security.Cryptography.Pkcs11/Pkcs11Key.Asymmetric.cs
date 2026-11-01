using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Key
{
    // === Public-key export and key agreement ==================================

    // The operation name the export's attribute errors carry.
    private const string ExportOperation = "Pkcs11Key.Export";

    /// <summary>
    /// Exports this key's public half in <paramref name="format"/>, read from the public-key handle when
    /// there is one and from the private-key handle otherwise. Nothing private is ever exported.
    /// </summary>
    /// <remarks>
    /// <list type="table">
    /// <listheader><term>Key type</term><description><see cref="Pkcs11KeyBlobFormat.RawPublicKey"/></description></listheader>
    /// <item><term><see cref="CKK.CKK_EC"/> (named curve)</term><description>The uncompressed point <c>0x04 ‖ X ‖ Y</c>.</description></item>
    /// <item><term><see cref="CKK.CKK_RSA"/></term><description>PKCS#1 <c>RSAPublicKey</c>, as <see cref="RSA.ExportRSAPublicKey"/> writes it.</description></item>
    /// <item><term><see cref="CKK.CKK_DSA"/></term><description>The public value as <c>INTEGER y</c> (RFC 3279); the domain parameters are only in the <c>SubjectPublicKeyInfo</c>.</description></item>
    /// <item><term><see cref="CKK.CKK_EC_EDWARDS"/>, <see cref="CKK.CKK_EC_MONTGOMERY"/></term><description>The Ed25519 / Ed448 (RFC 8032) or X25519 / X448 (RFC 7748) public key; the <c>SubjectPublicKeyInfo</c> is RFC 8410's, the curve's OID with no parameters. The curve is read from <c>CKA_EC_PARAMS</c>, as the RFC 8410 OID or the PKCS#11 curve name; <c>CKA_EC_POINT</c> may hold the key raw or in an OCTET STRING.</description></item>
    /// <item><term><see cref="CKK.CKK_ML_DSA"/>, <see cref="CKK.CKK_SLH_DSA"/>, <see cref="CKK.CKK_ML_KEM"/></term><description>The FIPS 204 / 205 / 203 public-key encoding; the <c>SubjectPublicKeyInfo</c> names the parameter set by OID.</description></item>
    /// </list>
    /// <para>
    /// Where <c>CKA_VALUE</c> is the public key (DSA and the FIPS 203/204/205 types) it is read from the
    /// public-key handle only: on the private-key object the same attribute is the private value.
    /// </para>
    /// </remarks>
    /// <param name="format">The encoding to write.</param>
    /// <returns>The encoded public key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="format"/> is not a defined <see cref="Pkcs11KeyBlobFormat"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <see cref="KeyType"/> is not supported.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Thrown when the public attributes are sensitive, cannot be read from any available handle, or
    /// cannot be parsed; <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when an RSA or DSA integer the token
    /// returned is empty or zero, or an Edwards or Montgomery key's <c>CKA_EC_PARAMS</c> names none of its
    /// curves or its <c>CKA_EC_POINT</c> is not a key of that curve's length; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.
    /// </exception>
    public byte[] Export(Pkcs11KeyBlobFormat format)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (format is not (Pkcs11KeyBlobFormat.SubjectPublicKeyInfo or Pkcs11KeyBlobFormat.RawPublicKey))
            throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown key blob format.");

        bool spki = format == Pkcs11KeyBlobFormat.SubjectPublicKeyInfo;
        return _keyType switch
        {
            CKK.CKK_EC => ExportEc(spki),
            CKK.CKK_RSA => ExportRsa(spki),
            CKK.CKK_DSA => ExportDsa(spki),
            CKK.CKK_EC_EDWARDS or CKK.CKK_EC_MONTGOMERY => ExportRfc8410(spki),
            CKK.CKK_ML_DSA or CKK.CKK_SLH_DSA or CKK.CKK_ML_KEM => ExportPostQuantum(spki),
            _ => throw new NotSupportedException(
                $"Pkcs11Key.Export supports CKK_EC, CKK_RSA, CKK_DSA, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_ML_DSA, CKK_SLH_DSA and CKK_ML_KEM keys; this key is {_keyType}."),
        };
    }

    private byte[] ExportEc(bool spki)
    {
        ECParameters ec = Pkcs11PublicKeyView.ReadEcPublicKey(this, ExportOperation);
        return spki ? SubjectPublicKeyInfoEncoding.EncodeEc(ec) : EcPointEncoding.EncodeUncompressedPoint(ec.Q.X, ec.Q.Y);
    }

    private byte[] ExportRsa(bool spki)
    {
        // The modulus and public exponent are public on either half, so the private-key handle
        // is a valid source for a key without a public companion.
        using var attrs = GetAttributeValue(CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.Export (CKA_MODULUS / CKA_PUBLIC_EXPONENT not readable from any available handle)");
        byte[] modulus = PublicKeySynthesis.RequirePublicInteger(attrs[0].GetValueAsByteArray(), CKA.CKA_MODULUS, ExportOperation);
        byte[] exponent = PublicKeySynthesis.RequirePublicInteger(attrs[1].GetValueAsByteArray(), CKA.CKA_PUBLIC_EXPONENT, ExportOperation);
        return spki
            ? SubjectPublicKeyInfoEncoding.EncodeRsa(modulus, exponent)
            : SubjectPublicKeyInfoEncoding.EncodeRsaPublicKey(modulus, exponent);
    }

    private byte[] ExportDsa(bool spki)
    {
        // Domain parameters are public on either half.
        using var domain = GetAttributeValue(CKA.CKA_PRIME, CKA.CKA_SUBPRIME, CKA.CKA_BASE);
        if (domain[0].CannotBeRead || domain[1].CannotBeRead || domain[2].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.Export (CKA_PRIME / CKA_SUBPRIME / CKA_BASE not readable from any available handle)");
        byte[] y = PublicKeySynthesis.RequirePublicInteger(ReadPublicValue(), CKA.CKA_VALUE, ExportOperation);
        if (!spki)
            return SubjectPublicKeyInfoEncoding.EncodeDsaPublicKey(y);
        return SubjectPublicKeyInfoEncoding.EncodeDsa(
            PublicKeySynthesis.RequirePublicInteger(domain[0].GetValueAsByteArray(), CKA.CKA_PRIME, ExportOperation),
            PublicKeySynthesis.RequirePublicInteger(domain[1].GetValueAsByteArray(), CKA.CKA_SUBPRIME, ExportOperation),
            PublicKeySynthesis.RequirePublicInteger(domain[2].GetValueAsByteArray(), CKA.CKA_BASE, ExportOperation),
            y);
    }

    // RFC 8410: the curve from CKA_EC_PARAMS, the key from CKA_EC_POINT, both public on either half.
    private byte[] ExportRfc8410(bool spki)
    {
        using var attrs = GetAttributeValue(CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.Export (CKA_EC_PARAMS / CKA_EC_POINT not readable from any available handle)");
        Rfc8410Curve curve = Rfc8410Curves.Describe(_keyType, attrs[0].GetValueAsByteArray())
            ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                $"Pkcs11Key.Export (CKA_EC_PARAMS names no {_keyType} curve: Ed25519, Ed448, X25519 or X448)");
        byte[] key = EcPointEncoding.TryUnwrapRawKey(attrs[1].GetValueAsByteArray(), curve.KeyLength)
            ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                $"Pkcs11Key.Export (CKA_EC_POINT is not a {curve.KeyLength}-byte {curve.Name} key, raw or in an OCTET STRING)");
        return spki ? SubjectPublicKeyInfoEncoding.EncodeWithoutParameters(curve.Oid, key) : key;
    }

    private byte[] ExportPostQuantum(bool spki)
    {
        using var parameterSet = GetAttributeValue(CKA.CKA_PARAMETER_SET);
        if (parameterSet[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.Export (CKA_PARAMETER_SET not readable)");
        ulong set = parameterSet[0].GetValueAsUlong();
        (string oid, int length) = PostQuantumParameterSets.Describe(_keyType, set)
            ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                $"Pkcs11Key.Export (unrecognized {_keyType} parameter set 0x{set:X})");

        byte[] publicKey = ReadPublicValue();
        if (publicKey.Length != length)
            throw Pkcs11Exception.Create(CKR.CKR_GENERAL_ERROR,
                $"Pkcs11Key.Export (token returned a {publicKey.Length}-byte public key; parameter set 0x{set:X} has {length})");
        return spki ? SubjectPublicKeyInfoEncoding.EncodeWithoutParameters(oid, publicKey) : publicKey;
    }

    // CKA_VALUE of the public-key object. Never GetAttributeValue's fallback to the private-key handle:
    // there the same attribute is the private value, and a token that leaves it readable would hand it
    // back as the public key.
    private byte[] ReadPublicValue()
    {
        if (PublicHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Export (no public-key object; the private key's CKA_VALUE is the private value)");

        using var attrs = _session.Core.GetAttributeValue(PublicHandle, [CKA.CKA_VALUE]);
        if (attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.Export (public-key CKA_VALUE not readable)");
        return attrs[0].GetValueAsByteArray();
    }

    /// <summary>
    /// Key agreement with a peer public key, returning the raw shared secret. For a
    /// <see cref="CKK.CKK_EC"/> key: ECDH, <c>CKM_ECDH1_DERIVE</c> with <see cref="CKD.CKD_NULL"/>, the
    /// x-coordinate of the shared point Z, as many bytes as this key's field. For a
    /// <see cref="CKK.CKK_EC_MONTGOMERY"/> key: X25519 or X448 (RFC 7748), <c>CKM_ECDH1_DERIVE</c> with
    /// <see cref="CKD.CKD_NULL"/> and the peer's raw u-coordinate, the 32- or 56-byte shared secret. Apply a
    /// KDF to it before use as key material (NIST SP 800-56A, RFC 7748 §6); for an on-token key with the KDF
    /// applied, use <see cref="Pkcs11Session.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/>, which applies to
    /// <see cref="CKK.CKK_EC"/> keys only (an X25519 or X448 peer cannot use it).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The peer is a <c>SubjectPublicKeyInfo</c> because it names its own algorithm and curve, so it can
    /// always be validated before it reaches the token: it must be the same algorithm on this key's
    /// curve, its coordinates must match the field size, and the point must satisfy the curve equation.
    /// PKCS#11 does not require the token to check any of it, and an unchecked peer lets the
    /// invalid-curve / small-subgroup attack recover this key's private scalar.
    /// </para>
    /// <para>
    /// An X25519 / X448 peer must be an RFC 8410 <c>SubjectPublicKeyInfo</c> (<c>id-X25519</c> or
    /// <c>id-X448</c>, no parameters) for this key's curve, its key the curve's length. Every u-coordinate is
    /// on the curve or its twist, so the check that matters is for a low-order point, for which the secret is
    /// all zero whatever this key: u = 0 is refused before the token sees it, and an all-zero secret from the
    /// token is refused after (RFC 7748 §6). The curve is read from this key's <c>CKA_EC_PARAMS</c>, the
    /// RFC 8410 OID or the PKCS#11 v3.0 curve name (<c>curve25519</c> / <c>curve448</c>).
    /// </para>
    /// <para>
    /// The field size comes from this key, never from the peer: from the curve catalog, else from this
    /// key's own <c>CKA_EC_POINT</c>, so a peer with short coordinates cannot truncate the secret.
    /// </para>
    /// <para>
    /// The secret is derived into an extractable, non-sensitive session object, read and destroyed.
    /// The caller owns the returned array and should zero it
    /// (<see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>) once done.
    /// </para>
    /// </remarks>
    /// <param name="peerSubjectPublicKeyInfo">The peer's public key as a DER <c>SubjectPublicKeyInfo</c>; for EC, RFC 5480 with a named curve and an uncompressed point; for X25519 / X448, RFC 8410.</param>
    /// <returns>The raw shared secret.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="NotSupportedException">Thrown if <see cref="KeyType"/> is not supported.</exception>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the session's <see cref="Pkcs11Session.Policy"/> permits reading the shared secret
    /// off the token (<see cref="Policy.KeyMaterialExportKind.EcdhSharedSecret"/>) and creating the
    /// extractable, non-sensitive object it is read from. Checked before the peer is examined.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerSubjectPublicKeyInfo"/> is not a DER <c>SubjectPublicKeyInfo</c>, is an EC key without a named curve and an uncompressed point, or is an X25519 / X448 key with algorithm parameters.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if the peer's algorithm or curve does not match this key's, its coordinate or key lengths don't match the curve, its point does not satisfy the curve equation, or (X25519 / X448) it is u = 0 or the token returns an all-zero secret for it.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if this key's <c>CKA_EC_PARAMS</c> cannot be read (or, for a Montgomery key, names neither X25519 nor X448) or the derived value is not readable; otherwise propagated from <c>C_DeriveKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c>.</exception>
    /// <exception cref="CryptographicException">Thrown if the token returns a shared secret that is not the curve's length.</exception>
    public byte[] DeriveRawSecret(ReadOnlySpan<byte> peerSubjectPublicKeyInfo)
    {
        const string operation = "Pkcs11Key.DeriveRawSecret";
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireAgreementKeyType(operation);
        // The export check comes before the peer is examined, and it is what a policy that allows extractable
        // templates but not a plaintext shared secret relies on. Inside the read-back, the derivation's
        // extractable template and CKD_NULL are judged as this read-back.
        using SecretReadBack readBack = _session.BeginReadBack(Policy.KeyMaterialExportKind.EcdhSharedSecret);

        AgreementPeer peer = ValidateAgreementPeer(peerSubjectPublicKeyInfo, operation);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peer.PublicData));
        // The private key itself remains non-extractable; only the ephemeral secret object is not.
        using var template = Algorithms.DerivedKeyMaterial.ExtractableSecretTemplate(peer.SecretLength);

        // Z is a field element, always the field size long (SEC 1 §2.3.5; RFC 7748 §5 for X25519 / X448):
        // a token that drops its leading zero bytes (SoftHSM2 did before 8bc65b5) or returns more would
        // hand back a different secret, which the read-back's length check refuses.
        return readBack.Read(
            () => Derive(mechanism, template),
            peer.SecretLength,
            RawSecretFailures,
            _keyType == CKK.CKK_EC_MONTGOMERY ? RefuseAllZeroSecret : null);
    }

    private static readonly ReadBackFailures RawSecretFailures = new(
        () => Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE, "Pkcs11Key.DeriveRawSecret (derived CKA_VALUE not readable)"),
        (actual, expected) => new CryptographicException(
            $"The token returned a {actual}-byte shared secret; this curve's is {expected} bytes."));

    // RFC 7748 §6.1: a low-order peer gives an all-zero X25519 / X448 secret whatever the private key. u = 0
    // was refused before the token saw it; the other low-order points are caught here, since PKCS#11 does not
    // require the token to check.
    private static void RefuseAllZeroSecret(byte[] secret)
    {
        if (MontgomeryPeerValidator.IsZero(secret))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                "Pkcs11Key.DeriveRawSecret (peer public key is a low-order point: the shared secret is all zero)");
    }

    /// <summary>
    /// Key agreement with a peer public key that keeps the shared secret on the token: the result is
    /// a session <see cref="CKK.CKK_GENERIC_SECRET"/> key holding the raw secret Z, sensitive,
    /// non-extractable and usable only as the base key of a further derivation. Turn it into working keys
    /// with <see cref="Derive(Mechanism, Objects.ObjectTemplate)"/> and a KDF, e.g. <c>CKM_HKDF_DERIVE</c> (<see cref="MechanismParams.CkmHkdfParams"/>),
    /// one derivation per key; no secret byte reaches the process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The PKCS#11 counterpart of CNG's <c>NCryptSecretAgreement</c> secret handle. For a
    /// <see cref="CKK.CKK_EC"/> key: <c>CKM_ECDH1_DERIVE</c> with <see cref="CKD.CKD_NULL"/>, Z the
    /// x-coordinate of the shared point, as many bytes as this key's field.
    /// </para>
    /// <para>
    /// The peer is validated exactly as for <see cref="DeriveRawSecret"/>.
    /// </para>
    /// <para>
    /// Permitted by the default policies, which otherwise refuse <see cref="CKD.CKD_NULL"/>: the result
    /// has <c>CKA_ENCRYPT</c>, <c>CKA_DECRYPT</c>, <c>CKA_SIGN</c>, <c>CKA_VERIFY</c>, <c>CKA_WRAP</c> and
    /// <c>CKA_UNWRAP</c> false, so Z can never be used as a key itself (SP 800-56A), only through a KDF
    /// the policy approves. For SP 800-56C two-step derivation, run the extraction step first
    /// (<c>CKM_HKDF_DERIVE</c> with extract, or extract-and-expand); the policy judges the KDF mechanism
    /// and its PRF, not which step the caller runs on Z.
    /// </para>
    /// </remarks>
    /// <param name="peerSubjectPublicKeyInfo">The peer's public key as a DER <c>SubjectPublicKeyInfo</c>; for EC, RFC 5480 with a named curve and an uncompressed point.</param>
    /// <returns>The on-token shared secret. Dispose releases the wrapper; <see cref="Destroy"/> removes it from the token before the session closes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="NotSupportedException">Thrown if <see cref="KeyType"/> is not supported.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerSubjectPublicKeyInfo"/> is not a DER <c>SubjectPublicKeyInfo</c>, or is an EC key without a named curve and an uncompressed point.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if the peer's algorithm or curve does not match this key's, its coordinate lengths don't match the field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the session's <see cref="Pkcs11Session.Policy"/> refuses ECDH or this key's curve.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if this key's <c>CKA_EC_PARAMS</c> cannot be read; otherwise propagated from <c>C_DeriveKey</c>.</exception>
    public Pkcs11Key DeriveSecretAgreement(ReadOnlySpan<byte> peerSubjectPublicKeyInfo)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_keyType != CKK.CKK_EC)
            throw new NotSupportedException($"Pkcs11Key.DeriveSecretAgreement supports CKK_EC keys; this key is {_keyType}.");

        ValidatedEcdhPeer peer = ValidateEcPeer(peerSubjectPublicKeyInfo, "Pkcs11Key.DeriveSecretAgreement");
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peer.EncodedPoint));
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(peer.FieldSizeBytes)
            .Sensitive()
            .NonExtractable()
            .OnToken(false)
            .Derive()
            .Encrypt(false).Decrypt(false)
            .Sign(false).Verify(false)
            .Wrap(false).Unwrap(false)
            .Build();
        return Derive(mechanism, template);
    }

    private void RequireAgreementKeyType(string operationName)
    {
        if (_keyType is not (CKK.CKK_EC or CKK.CKK_EC_MONTGOMERY))
            throw new NotSupportedException($"{operationName} supports CKK_EC and CKK_EC_MONTGOMERY keys; this key is {_keyType}.");
    }

    // A validated peer as CKM_ECDH1_DERIVE takes it, and the length of the secret it agrees.
    private readonly record struct AgreementPeer(byte[] PublicData, int SecretLength);

    // The one peer-validation step of both agreements (DeriveRawSecret, DeriveSecretAgreement). For CKK_EC
    // the peer's point as a DER OCTET STRING and the field size; for CKK_EC_MONTGOMERY the raw u-coordinate,
    // as PKCS#11 v3.0's CK_ECDH1_DERIVE_PARAMS has it for Montgomery keys, and the curve's 32 or 56 bytes.
    private AgreementPeer ValidateAgreementPeer(ReadOnlySpan<byte> peerSubjectPublicKeyInfo, string operationName)
    {
        if (_keyType == CKK.CKK_EC_MONTGOMERY)
        {
            ValidatedMontgomeryPeer u = MontgomeryPeerValidator.Validate(
                this, peerSubjectPublicKeyInfo, nameof(peerSubjectPublicKeyInfo), operationName);
            return new AgreementPeer(u.U, u.SecretLength);
        }

        ValidatedEcdhPeer ec = ValidateEcPeer(peerSubjectPublicKeyInfo, operationName);
        return new AgreementPeer(ec.EncodedPoint, ec.FieldSizeBytes);
    }

    private ValidatedEcdhPeer ValidateEcPeer(ReadOnlySpan<byte> peerSubjectPublicKeyInfo, string operationName)
        => EcdhPeerValidator.Validate(
            this, DecodeEcPeer(peerSubjectPublicKeyInfo, operationName), nameof(peerSubjectPublicKeyInfo), operationName);

    // A malformed encoding is the caller's argument error; a well-formed key of another algorithm is a
    // mismatch with this key, reported like a curve mismatch.
    private static ECParameters DecodeEcPeer(ReadOnlySpan<byte> peerSubjectPublicKeyInfo, string operationName)
    {
        string? algorithm = SubjectPublicKeyInfoEncoding.TryReadAlgorithm(peerSubjectPublicKeyInfo)
            ?? throw new ArgumentException("Peer public key is not a DER SubjectPublicKeyInfo.", nameof(peerSubjectPublicKeyInfo));
        if (algorithm != Oids.KeyAlgorithms.EcPublicKey)
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key algorithm is {algorithm}, expected id-ecPublicKey)");
        if (!SubjectPublicKeyInfoEncoding.TryDecodeEc(peerSubjectPublicKeyInfo, out ECParameters ec))
            throw new ArgumentException(
                "Peer EC public key must name its curve (namedCurve) and carry an uncompressed point.", nameof(peerSubjectPublicKeyInfo));
        return ec;
    }
}
