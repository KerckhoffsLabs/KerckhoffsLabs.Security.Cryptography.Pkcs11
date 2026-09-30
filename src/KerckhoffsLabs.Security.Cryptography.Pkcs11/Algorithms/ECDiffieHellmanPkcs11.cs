using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

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
/// Z is read back with <see cref="Pkcs11Key.DeriveAndExportSecret"/>, which checks the peer point
/// against this key's curve and passes Z through an ephemeral session key it destroys; the private
/// key itself stays non-extractable. <see cref="DeriveKeyTls"/> is not supported (no public
/// TLS-PRF primitive). Private-parameter export is refused; <see cref="ExportParameters(bool)"/> with
/// <c>false</c> reads the public point from the token.
/// </para>
/// <para>
/// <b>Requires a policy that permits reading the ECDH shared secret off the token, e.g.
/// <c>CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, reason)</c>.</b> Every method here returns
/// <c>byte[]</c>, so the derived value must be read off the token — this adapter cannot be
/// implemented without extracting key material. The policy decides this as a
/// <see cref="KeyMaterialExportRequest"/>, which the default SecureOnly policy refuses; allowing that
/// one export kind is the narrow opt-in.
/// </para>
/// <para>
/// If the derived key never needs to leave the HSM, use
/// <see cref="Pkcs11Workspace.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/> instead: it
/// applies the KDF on the token and returns a sensitive key, so nothing is exported and no opt-in is
/// needed. Its KDFs are the ANSI X9.63 ones (<c>CKD_SHA*_KDF</c>, <c>H(Z ‖ counter)</c>), which do not
/// reproduce the <c>H(prepend ‖ Z ‖ append)</c> of <see cref="DeriveKeyFromHash(ECDiffieHellmanPublicKey, HashAlgorithmName, byte[], byte[])"/>
/// and <see cref="DeriveKeyFromHmac(ECDiffieHellmanPublicKey, HashAlgorithmName, byte[], byte[], byte[])"/>,
/// and PKCS#11 has no KDF that does. A protocol fixed to the BCL formula therefore has to export Z; one
/// that can choose its KDF should move to the on-token one.
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

        // Reflect the token key's real curve field size. Best-effort: the ECDiffieHellman base
        // constructor leaves KeySize=0 (via KeySizeValue), which we keep if the curve can't be
        // identified — callers relying on KeySize/LegalKeySizes would already be broken in that case.
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
            return key.GetEcCurve().FieldSizeBits;
        }
        catch (Exception ex) when (ex is CryptographicException or Pkcs11Exception)
        {
            // CKA_EC_PARAMS is not exposed, or not a named-curve OID — leave KeySize at the ECDiffieHellman
            // base-class default.
            return null;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="CryptographicException">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) cannot be read, or cannot be parsed as a named-curve uncompressed point.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/> has no X or Y coordinate, is on another curve than this key, has coordinates of the wrong length, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement.</exception>
    /// <exception cref="CryptographicException">Thrown when this key's curve, or the derived secret, cannot be read.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
        => DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, null, null);

    /// <inheritdoc/>
    /// <remarks>
    /// <para>Returns the raw shared secret Z (the x-coordinate), as the BCL does.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/> has no X or Y coordinate, is on another curve than this key, has coordinates of the wrong length, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement.</exception>
    /// <exception cref="CryptographicException">Thrown when this key's curve, or the derived secret, cannot be read.</exception>
    public override byte[] DeriveRawSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey)
    {
        ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
        return DeriveRawSecret(otherPartyPublicKey);
    }


    /// <inheritdoc/>
    /// <remarks>Computes <c>Hash(secretPrepend ‖ Z ‖ secretAppend)</c> over the raw agreement Z.</remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="hashAlgorithm"/> has no name, or <paramref name="otherPartyPublicKey"/> has no X or Y coordinate, is on another curve than this key, has coordinates of the wrong length, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement.</exception>
    /// <exception cref="CryptographicException">Thrown when this key's curve, or the derived secret, cannot be read.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="hashAlgorithm"/> has no name, or <paramref name="otherPartyPublicKey"/> has no X or Y coordinate, is on another curve than this key, has coordinates of the wrong length, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement.</exception>
    /// <exception cref="CryptographicException">Thrown when this key's curve, or the derived secret, cannot be read.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
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
        Pkcs11ECCurve localCurve = _key.GetEcCurve();
        // ForPeer keeps the peer's curve with its point; the derivation refuses a peer on another curve
        // or off this key's curve before anything reaches the token.
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peer));

        // Z is one field element. Its size comes from the local key, not the peer's coordinate
        // encoding, so a peer reporting a short X cannot truncate the secret; the peer's (now
        // point-checked) length is used only for a curve outside the library's catalog.
        int fieldSize = localCurve.FieldSizeBits is int bits ? (bits + 7) / 8 : peer.Q.X!.Length;
        byte[] z = new byte[fieldSize];
        _key.DeriveAndExportSecret(mechanism, z);
        return z;
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <c>true</c>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="CryptographicException">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) cannot be read, or cannot be parsed as a named-curve uncompressed point.</exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptoPolicyViolationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        return _key.ExportEcPublicParameters();
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
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException("Use Pkcs11Workspace.GenerateKey to generate keys on the token.");
}
