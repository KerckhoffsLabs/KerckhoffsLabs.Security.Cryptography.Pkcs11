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
    /// returned is empty or zero; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.
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
            CKK.CKK_ML_DSA or CKK.CKK_SLH_DSA or CKK.CKK_ML_KEM => ExportPostQuantum(spki),
            _ => throw new NotSupportedException(
                $"Pkcs11Key.Export supports CKK_EC, CKK_RSA, CKK_DSA, CKK_ML_DSA, CKK_SLH_DSA and CKK_ML_KEM keys; this key is {_keyType}."),
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
    /// x-coordinate of the shared point Z, as many bytes as this key's field. Apply a KDF to it before
    /// use as key material (NIST SP 800-56A); for an on-token key with the KDF applied, use
    /// <see cref="Pkcs11Session.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/>.
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
    /// The field size comes from this key, never from the peer: from the curve catalog, else from this
    /// key's own <c>CKA_EC_POINT</c>, so a peer with short coordinates cannot truncate the secret.
    /// </para>
    /// <para>
    /// The secret is derived into an extractable, non-sensitive session object, read and destroyed.
    /// The caller owns the returned array and should zero it
    /// (<see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>) once done.
    /// </para>
    /// </remarks>
    /// <param name="peerSubjectPublicKeyInfo">The peer's public key as a DER <c>SubjectPublicKeyInfo</c>; for EC, RFC 5480 with a named curve and an uncompressed point.</param>
    /// <returns>The raw shared secret.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="NotSupportedException">Thrown if <see cref="KeyType"/> is not supported.</exception>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the session's <see cref="Pkcs11Session.Policy"/> permits reading the shared secret
    /// off the token (<see cref="Policy.KeyMaterialExportKind.EcdhSharedSecret"/>) and creating the
    /// extractable, non-sensitive object it is read from. Checked before the peer is examined.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerSubjectPublicKeyInfo"/> is not a DER <c>SubjectPublicKeyInfo</c>, or is an EC key without a named curve and an uncompressed point.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if the peer's algorithm or curve does not match this key's, its coordinate lengths don't match the field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if this key's <c>CKA_EC_PARAMS</c> cannot be read or the derived value is not readable; otherwise propagated from <c>C_DeriveKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c>.</exception>
    /// <exception cref="CryptographicException">Thrown if the token returns a shared secret that is not the curve's field size long.</exception>
    public byte[] DeriveRawSecret(ReadOnlySpan<byte> peerSubjectPublicKeyInfo)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_keyType != CKK.CKK_EC)
            throw new NotSupportedException($"Pkcs11Key.DeriveRawSecret supports CKK_EC keys; this key is {_keyType}.");
        _session.Enforce(new Policy.KeyMaterialExportRequest(Policy.KeyMaterialExportKind.EcdhSharedSecret));

        ValidatedEcdhPeer peer = ValidateEcPeer(peerSubjectPublicKeyInfo, "Pkcs11Key.DeriveRawSecret");

        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peer.EncodedPoint));
        // Raw secret read-back: derive an extractable, non-sensitive session generic secret of the
        // field size. The private key itself remains non-extractable.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(peer.FieldSizeBytes)
            .Extractable()
            .Sensitive(false)
            .Build();

        // The template asks for an extractable, non-sensitive key, so the policy also judges it as a
        // key template on this Derive; the export check above is what a policy that allows such
        // templates but not a plaintext shared secret relies on.
        Pkcs11Key derived = Derive(mechanism, template);
        bool operationFailed = true;
        try
        {
            // ObjectAttribute owns an unmanaged buffer holding the shared secret Z; disposing the
            // list is what frees and zeroizes it.
            using var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            if (attrs.Count == 0 || attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "Pkcs11Key.DeriveRawSecret (derived CKA_VALUE not readable)");
            byte[] secret = attrs[0].GetValueAsByteArray();

            // Z is a field element, always the field size long (SEC 1 §2.3.5). A token that drops its leading
            // zero bytes (SoftHSM2 did before 8bc65b5) or returns more would hand back a different secret.
            if (secret.Length != peer.FieldSizeBytes)
            {
                CryptographicOperations.ZeroMemory(secret);
                throw new CryptographicException(
                    $"The token returned a {secret.Length}-byte ECDH shared secret; this curve's is {peer.FieldSizeBytes} bytes.");
            }
            operationFailed = false;
            return secret;
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    /// <summary>
    /// Key agreement with a peer public key that keeps the shared secret on the token: the result is
    /// a session <see cref="CKK.CKK_GENERIC_SECRET"/> key holding the raw secret Z, sensitive,
    /// non-extractable and usable only as the base key of a further derivation. Turn it into working keys
    /// with <see cref="Derive"/> and a KDF, e.g. <c>CKM_HKDF_DERIVE</c> (<see cref="MechanismParams.CkmHkdfParams"/>),
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

    /// <summary>
    /// Destroys an ephemeral derived key without letting a cleanup failure hide a real one.
    /// </summary>
    /// <remarks>
    /// A throw from <see langword="finally"/> <i>replaces</i> an exception already in flight, so a failed
    /// <c>C_DestroyObject</c> would reach the caller in place of whatever actually went wrong. This
    /// suppresses the destroy failure only on that path: when the operation succeeded, the destroy
    /// failure is the only news and is allowed to surface. The key is a session object either way, so
    /// the token collects it at <c>C_CloseSession</c> even when the eager destroy fails.
    /// </remarks>
    private static void DestroyEphemeral(Pkcs11Key derived, bool operationFailed)
    {
        using (derived)
        {
            try
            {
                derived.Destroy();
            }
            catch (Pkcs11Exception) when (operationFailed)
            {
                // Deliberately swallowed: see the remarks. The primary exception is the useful one.
            }
        }
    }
}
