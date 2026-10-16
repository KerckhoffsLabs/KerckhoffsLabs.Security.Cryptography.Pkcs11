using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Key
{
    // === Public-key export and key agreement ==================================

    /// <summary>
    /// Exports this key's public half in <paramref name="format"/>, read from the public-key handle when
    /// there is one and from the private-key handle otherwise. Nothing private is ever exported.
    /// </summary>
    /// <remarks>
    /// <list type="table">
    /// <listheader><term>Key type</term><description><see cref="Pkcs11KeyBlobFormat.RawPublicKey"/></description></listheader>
    /// <item><term><see cref="CKK.CKK_EC"/> (named curve)</term><description>The uncompressed point <c>0x04 ‖ X ‖ Y</c>.</description></item>
    /// <item><term><see cref="CKK.CKK_RSA"/></term><description>PKCS#1 <c>RSAPublicKey</c>, as <see cref="RSA.ExportRSAPublicKey"/> writes it.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="format">The encoding to write.</param>
    /// <returns>The encoded public key.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="format"/> is not a defined <see cref="Pkcs11KeyBlobFormat"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown if <see cref="KeyType"/> is not supported.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Thrown when the public attributes are sensitive, cannot be read from any available handle, or
    /// cannot be parsed; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.
    /// </exception>
    public byte[] Export(Pkcs11KeyBlobFormat format)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (format is not (Pkcs11KeyBlobFormat.SubjectPublicKeyInfo or Pkcs11KeyBlobFormat.RawPublicKey))
            throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown key blob format.");

        bool spki = format == Pkcs11KeyBlobFormat.SubjectPublicKeyInfo;
        switch (_keyType)
        {
            case CKK.CKK_EC:
                {
                    ECParameters ec = Pkcs11PublicKeyView.ReadEcPublicKey(this, "Pkcs11Key.Export");
                    return spki ? SubjectPublicKeyInfoEncoding.EncodeEc(ec) : [0x04, .. ec.Q.X!, .. ec.Q.Y!];
                }
            case CKK.CKK_RSA:
                {
                    // The modulus and public exponent are public on either half, so the private-key handle
                    // is a valid source for a key without a public companion.
                    using var attrs = GetAttributeValue(CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT);
                    if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                        throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                            "Pkcs11Key.Export (CKA_MODULUS / CKA_PUBLIC_EXPONENT not readable from any available handle)");
                    byte[] modulus = attrs[0].GetValueAsByteArray();
                    byte[] exponent = attrs[1].GetValueAsByteArray();
                    return spki
                        ? SubjectPublicKeyInfoEncoding.EncodeRsa(modulus, exponent)
                        : SubjectPublicKeyInfoEncoding.EncodeRsaPublicKey(modulus, exponent);
                }
            default:
                throw new NotSupportedException($"Pkcs11Key.Export supports CKK_EC and CKK_RSA keys; this key is {_keyType}.");
        }
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
    public byte[] DeriveRawSecret(ReadOnlySpan<byte> peerSubjectPublicKeyInfo)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_keyType != CKK.CKK_EC)
            throw new NotSupportedException($"Pkcs11Key.DeriveRawSecret supports CKK_EC keys; this key is {_keyType}.");
        _session.Enforce(new Policy.KeyMaterialExportRequest(Policy.KeyMaterialExportKind.EcdhSharedSecret));

        ECParameters peerKey = DecodeEcPeer(peerSubjectPublicKeyInfo);
        ValidatedEcdhPeer peer = EcdhPeerValidator.Validate(
            this, peerKey, nameof(peerSubjectPublicKeyInfo), "Pkcs11Key.DeriveRawSecret");

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
            operationFailed = false;
            return secret;
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    // A malformed encoding is the caller's argument error; a well-formed key of another algorithm is a
    // mismatch with this key, reported like a curve mismatch.
    private static ECParameters DecodeEcPeer(ReadOnlySpan<byte> peerSubjectPublicKeyInfo)
    {
        string? algorithm = SubjectPublicKeyInfoEncoding.TryReadAlgorithm(peerSubjectPublicKeyInfo)
            ?? throw new ArgumentException("Peer public key is not a DER SubjectPublicKeyInfo.", nameof(peerSubjectPublicKeyInfo));
        if (algorithm != SubjectPublicKeyInfoEncoding.EcPublicKeyOid)
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"Pkcs11Key.DeriveRawSecret (peer public key algorithm is {algorithm}, expected id-ecPublicKey)");
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
