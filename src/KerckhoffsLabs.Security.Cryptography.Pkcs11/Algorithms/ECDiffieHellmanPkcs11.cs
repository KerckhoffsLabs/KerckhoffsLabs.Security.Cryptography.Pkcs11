using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned ECDiffieHellman provider backed by a PKCS#11 <see cref="Pkcs11Key"/> (an EC private
/// key). Does NOT take ownership of the underlying key.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="ECDiffieHellman"/> so callers can pass this instance anywhere a BCL
/// <c>ECDiffieHellman</c> is accepted. Key agreement forwards to <c>CKM_ECDH1_DERIVE</c> with
/// <see cref="CKD.CKD_NULL"/> — the token computes the raw shared secret Z (the x-coordinate) using
/// the non-extractable private key — and the requested KDF (hash / HMAC) is then applied on the
/// managed side. This keeps the long-term private key on the token while matching the BCL's
/// <c>DeriveKeyFromHash</c> / <c>DeriveKeyFromHmac</c> semantics, and works with tokens (such as
/// SoftHSM) that only implement the <c>CKD_NULL</c> KDF.
/// </para>
/// <para>
/// To read Z back the raw agreement is derived into an extractable session generic-secret; the
/// private key itself stays non-extractable. <see cref="DeriveKeyTls"/> is not supported (no public
/// TLS-PRF primitive). Private-parameter export is refused; <see cref="ExportParameters(bool)"/> with
/// <c>false</c> reads the public point from the token.
/// </para>
/// </remarks>
public sealed class ECDiffieHellmanPkcs11 : ECDiffieHellman
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a PKCS#11 EC key as a BCL <see cref="ECDiffieHellman"/> instance. Does not take
    /// ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is
    /// <see cref="CKK.CKK_EC"/> and whose private half has <c>CKA_DERIVE</c> set.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an EC key.</exception>
    public ECDiffieHellmanPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_EC)
            throw new ArgumentException($"Expected an EC key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <inheritdoc/>
    public override ECDiffieHellmanPublicKey PublicKey
    {
        get
        {
            ECParameters publicParams = ExportParameters(includePrivateParameters: false);
            using var ecdh = Create(publicParams);
            return ecdh.PublicKey;
        }
    }

    // -----------------------------------------------------------------------
    // Key agreement
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Hashes the raw agreement Z with SHA-256, matching the BCL's legacy default.</remarks>
    public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
        => DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, null, null);

    /// <inheritdoc/>
    /// <remarks>Returns the raw shared secret Z (the x-coordinate), as the BCL does.</remarks>
    public override byte[] DeriveRawSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey)
    {
        ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
        return DeriveRawSecret(otherPartyPublicKey);
    }

    /// <inheritdoc/>
    /// <remarks>Computes <c>Hash(secretPrepend ‖ Z ‖ secretAppend)</c> over the raw agreement Z.</remarks>
    public override byte[] DeriveKeyFromHash(
        ECDiffieHellmanPublicKey otherPartyPublicKey,
        HashAlgorithmName hashAlgorithm,
        byte[]? secretPrepend,
        byte[]? secretAppend)
    {
        ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
        if (string.IsNullOrEmpty(hashAlgorithm.Name))
            throw new ArgumentException("Hash algorithm must be specified.", nameof(hashAlgorithm));

        byte[] z = DeriveRawSecret(otherPartyPublicKey);
        try
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
            if (secretPrepend is not null) hash.AppendData(secretPrepend);
            hash.AppendData(z);
            if (secretAppend is not null) hash.AppendData(secretAppend);
            return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Computes <c>HMAC(key, secretPrepend ‖ Z ‖ secretAppend)</c> over the raw agreement Z, where the
    /// HMAC key is <paramref name="hmacKey"/>, or Z itself when <paramref name="hmacKey"/> is null
    /// (matching the BCL).
    /// </remarks>
    public override byte[] DeriveKeyFromHmac(
        ECDiffieHellmanPublicKey otherPartyPublicKey,
        HashAlgorithmName hashAlgorithm,
        byte[]? hmacKey,
        byte[]? secretPrepend,
        byte[]? secretAppend)
    {
        ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
        if (string.IsNullOrEmpty(hashAlgorithm.Name))
            throw new ArgumentException("Hash algorithm must be specified.", nameof(hashAlgorithm));

        byte[] z = DeriveRawSecret(otherPartyPublicKey);
        try
        {
            byte[] key = hmacKey ?? z; // null key => use the shared secret as the HMAC key
            using IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithm, key);
            if (secretPrepend is not null) hmac.AppendData(secretPrepend);
            hmac.AppendData(z);
            if (secretAppend is not null) hmac.AppendData(secretAppend);
            return hmac.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Always thrown. The TLS-1.0/1.1 PRF is not exposed as a public primitive, so it cannot be
    /// applied to a token-derived secret here. Derive the raw secret and run the PRF yourself.
    /// </exception>
    public override byte[] DeriveKeyTls(
        ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] prfLabel, byte[] prfSeed)
        => throw new NotSupportedException(
            "ECDiffieHellmanPkcs11 does not support DeriveKeyTls (no public TLS-PRF primitive). " +
            "Use DeriveKeyFromHash / DeriveKeyFromHmac, or DeriveRawSecretAgreement plus your own PRF.");

    private byte[] DeriveRawSecret(ECDiffieHellmanPublicKey otherPartyPublicKey)
    {
        ECParameters peer = otherPartyPublicKey.ExportParameters();
        byte[] x = peer.Q.X ?? throw new ArgumentException("Peer public key has no X coordinate.", nameof(otherPartyPublicKey));
        byte[] y = peer.Q.Y ?? throw new ArgumentException("Peer public key has no Y coordinate.", nameof(otherPartyPublicKey));
        int fieldSize = x.Length;

        byte[] peerPoint = EncodeEcPointAsDerOctetString(x, y);
        using var p = new CkmEcdh1DeriveParams(CKD.CKD_NULL, peerPoint);
        using var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);
        // Raw secret read-back: derive an extractable, non-sensitive session generic secret of the
        // field size. The private key itself remains non-extractable.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(fieldSize)
            .Extractable()
            .Sensitive(false)
            .Build();

        Pkcs11Key derived = _key.DeriveExtractable(mech, template);
        try
        {
            var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            try
            {
                if (attrs.Count == 0 || attrs[0].CannotBeRead)
                    throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                        "ECDiffieHellmanPkcs11.DeriveRawSecret (derived CKA_VALUE not readable)");
                return attrs[0].GetValueAsByteArray();
            }
            finally
            {
                // ObjectAttribute owns an unmanaged buffer holding the shared secret Z; free it.
                foreach (var a in attrs) a.Dispose();
            }
        }
        finally
        {
            derived.Delete();
            derived.Dispose();
        }
    }

    /// <summary>
    /// Encodes an uncompressed EC point (0x04 ‖ X ‖ Y) as a DER OCTET STRING, the form PKCS#11 expects
    /// for the ECDH1 public-data parameter (the full <c>CKA_EC_POINT</c> value).
    /// </summary>
    private static byte[] EncodeEcPointAsDerOctetString(byte[] x, byte[] y)
    {
        byte[] raw = new byte[1 + x.Length + y.Length];
        raw[0] = 0x04;
        x.CopyTo(raw, 1);
        y.CopyTo(raw, 1 + x.Length);

        if (raw.Length < 0x80)
        {
            byte[] der = new byte[2 + raw.Length];
            der[0] = 0x04;
            der[1] = (byte)raw.Length;
            raw.CopyTo(der, 2);
            return der;
        }
        else
        {
            // Long-form length (one length byte covers all named curves up to 255-byte points).
            byte[] der = new byte[3 + raw.Length];
            der[0] = 0x04;
            der[1] = 0x81;
            der[2] = (byte)raw.Length;
            raw.CopyTo(der, 3);
            return der;
        }
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <c>true</c>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        var attrs = _key.GetAttributeValue(CKA.CKA_EC_POINT, CKA.CKA_EC_PARAMS);
        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "ECDiffieHellmanPkcs11.ExportParameters (CKA_EC_POINT / CKA_EC_PARAMS not readable)");

            var ec = Pkcs11PublicKeyView.TryParseEcPublicKey(
                attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
            return ec ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                "ECDiffieHellmanPkcs11.ExportParameters (CKA_EC_POINT / CKA_EC_PARAMS could not be parsed as a named-curve uncompressed point)");
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        => throw new NotSupportedException(
            "Explicit (non-named-curve) parameter export is not supported. Use ExportParameters(false).");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(ECParameters parameters)
        => throw new NotSupportedException(
            "ECDiffieHellmanPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Workspace.ImportKey or GenerateKey instead.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void GenerateKey(BclECCurve curve)
        => throw new NotSupportedException("Use Pkcs11Workspace.GenerateKey to generate keys on the token.");
}
