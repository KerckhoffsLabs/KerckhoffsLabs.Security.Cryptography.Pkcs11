using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Key
{
    // === EC (CKK_EC) keys ==================================================

    /// <summary>
    /// Reads this key's curve from <c>CKA_EC_PARAMS</c>, resolved through the library's
    /// <see cref="Pkcs11LibraryOptions.CurveCatalog"/>: a curve the catalog lists carries its name and
    /// <see cref="Pkcs11ECCurve.FieldSizeBits"/>, any other carries only its OID.
    /// </summary>
    /// <remarks>Reads the attribute on every call (one <c>C_GetAttributeValue</c>); nothing is cached.</remarks>
    /// <returns>The key's named curve.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="KeyType"/> is not <see cref="CKK.CKK_EC"/>.</exception>
    /// <exception cref="Pkcs11Exception">
    /// <see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/> when <c>CKA_EC_PARAMS</c> cannot be read,
    /// <see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when it is not a DER-encoded named-curve OID;
    /// otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.
    /// </exception>
    public Pkcs11ECCurve GetCurve()
    {
        ThrowUnlessEc(nameof(GetCurve));

        using var attrs = GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "Pkcs11Key.GetCurve (CKA_EC_PARAMS not readable)");

        Pkcs11ECCurve curve;
        try
        {
            curve = Pkcs11ECCurve.FromEcParams(attrs[0].GetValueAsByteArray());
        }
        catch (ArgumentException)
        {
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                "Pkcs11Key.GetCurve (CKA_EC_PARAMS is not a DER-encoded named-curve OID)");
        }
        return _session.Library.CurveCatalog.Resolve(curve);
    }

    /// <summary>
    /// Reads this key's public key (<c>CKA_EC_POINT</c> and <c>CKA_EC_PARAMS</c>) as
    /// <see cref="ECParameters"/>, from the public-key handle when there is one and from the
    /// private-key handle otherwise. <see cref="ECParameters.D"/> is always <see langword="null"/>:
    /// only public attributes are read.
    /// </summary>
    /// <returns>The named curve and the uncompressed public point.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="KeyType"/> is not <see cref="CKK.CKK_EC"/>.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Thrown when the attributes are sensitive, cannot be read from any available handle, or cannot be
    /// parsed as a named-curve uncompressed point.
    /// </exception>
    public ECParameters ExportEcPublicKey()
    {
        ThrowUnlessEc(nameof(ExportEcPublicKey));
        return Pkcs11PublicKeyView.ReadEcPublicKey(this, "Pkcs11Key.ExportEcPublicKey");
    }

    /// <summary>
    /// ECDH key agreement with <paramref name="peerPublicKey"/> that returns the raw shared secret Z:
    /// the x-coordinate of the shared point, <c>CKM_ECDH1_DERIVE</c> with <see cref="CKD.CKD_NULL"/>,
    /// as many bytes as this key's field. Apply a KDF to it before use as key material
    /// (NIST SP 800-56A); for an on-token key with the KDF applied, use
    /// <see cref="Pkcs11Session.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="peerPublicKey"/> is validated before it reaches the token: it must be on this
    /// key's curve, its coordinates must match the field size, and the point must satisfy the curve
    /// equation. PKCS#11 does not require the token to check any of it, and an unchecked peer lets the
    /// invalid-curve / small-subgroup attack recover this key's private scalar.
    /// </para>
    /// <para>
    /// The field size comes from this key, never from the peer: from the curve catalog, else from this
    /// key's own <c>CKA_EC_POINT</c>, so a peer reporting short coordinates cannot truncate the secret.
    /// </para>
    /// <para>
    /// The secret is derived into an extractable, non-sensitive session object, read and destroyed.
    /// The caller owns the returned array and should zero it
    /// (<see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>) once done.
    /// </para>
    /// </remarks>
    /// <param name="peerPublicKey">The peer's public key. <see cref="ECParameters.Curve"/> and both coordinates of <see cref="ECParameters.Q"/> are required.</param>
    /// <returns>The raw shared secret, field-size bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="KeyType"/> is not <see cref="CKK.CKK_EC"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the session's <see cref="Pkcs11Session.Policy"/> permits reading an ECDH shared
    /// secret off the token (<see cref="KeyMaterialExportKind.EcdhSharedSecret"/>) and creating the
    /// extractable, non-sensitive object it is read from.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="peerPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="peerPublicKey"/>'s curve does not match this key's, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Thrown if this key's <c>CKA_EC_PARAMS</c> cannot be read or the derived value is not readable; otherwise propagated from <c>C_DeriveKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c>.</exception>
    public byte[] DeriveRawSecretEcdh(ECParameters peerPublicKey)
    {
        ThrowUnlessEc(nameof(DeriveRawSecretEcdh));
        _session.Enforce(new KeyMaterialExportRequest(KeyMaterialExportKind.EcdhSharedSecret));

        ValidatedEcdhPeer peer = EcdhPeerValidator.Validate(
            this, peerPublicKey, nameof(peerPublicKey), "Pkcs11Key.DeriveRawSecretEcdh");

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
                    "Pkcs11Key.DeriveRawSecretEcdh (derived CKA_VALUE not readable)");
            byte[] secret = attrs[0].GetValueAsByteArray();
            operationFailed = false;
            return secret;
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    private void ThrowUnlessEc(string operation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_keyType != CKK.CKK_EC)
            throw new InvalidOperationException($"Pkcs11Key.{operation} requires a CKK_EC key; this key is {_keyType}.");
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
