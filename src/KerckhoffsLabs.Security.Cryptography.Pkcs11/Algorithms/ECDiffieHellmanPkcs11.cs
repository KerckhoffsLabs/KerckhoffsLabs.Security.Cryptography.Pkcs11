using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

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
/// <see langword="false"/> reads the public point from the token.
/// </para>
/// <para>
/// <b>Requires a policy that permits reading key material off the token, e.g.
/// <c>Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)</c>.</b> Every method here returns
/// <c>byte[]</c>, so the derived value must be read off the token — this adapter cannot be
/// implemented without extracting key material. The refusal comes from the library's single
/// secure-defaults gate, which declines to create the extractable, non-sensitive key the
/// read-back needs. Scope the policy override to one operation, or stay on the on-token
/// <c>Pkcs11Key.Derive</c> path if the derived key never needs to leave the HSM.
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <see langword="null"/>.</exception>
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
            return key.GetCurve().FieldSizeBits;
        }
        catch (Pkcs11Exception)
        {
            // CKA_EC_PARAMS unreadable or not a named-curve OID — leave KeySize at the ECDiffieHellman base-class default.
            return null;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="Pkcs11Exception">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) is sensitive, cannot be read, or cannot be parsed as a named-curve uncompressed point.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/>'s curve does not match this key's, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement, or thrown when the derived secret cannot be read back.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's session's <see cref="Pkcs11Session.Policy"/> refuses it: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
        => DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, null, null);

    /// <inheritdoc/>
    /// <remarks>
    /// <para>Returns the raw shared secret Z (the x-coordinate), as the BCL does.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/>'s curve does not match this key's, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement, or thrown when the derived secret cannot be read back.</exception>
    public override byte[] DeriveRawSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey)
    {
        ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
        return DeriveRawSecret(otherPartyPublicKey);
    }


    /// <inheritdoc/>
    /// <remarks>Computes <c>Hash(secretPrepend ‖ Z ‖ secretAppend)</c> over the raw agreement Z.</remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="hashAlgorithm"/> has no name, or <paramref name="otherPartyPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/>'s curve does not match this key's, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement, or thrown when the derived secret cannot be read back.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="otherPartyPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="hashAlgorithm"/> has no name, or <paramref name="otherPartyPublicKey"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11ArgumentException">Thrown if <paramref name="otherPartyPublicKey"/>'s curve does not match this key's, its coordinate lengths don't match that curve's field size, or its point does not satisfy the curve equation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> agreement, or thrown when the derived secret cannot be read back.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown when the wrapped key's session's <see cref="Pkcs11Session.Policy"/> refuses it: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
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

    // Peer validation, the export policy check and the read-back all happen in the façade: see
    // Pkcs11Key.DeriveRawSecretEcdh. The field size comes from the local key, not the peer's
    // coordinate encoding, so a subclassed ECDiffieHellmanPublicKey reporting a short X cannot
    // truncate the secret.
    private byte[] DeriveRawSecret(ECDiffieHellmanPublicKey otherPartyPublicKey)
        => _key.DeriveRawSecretEcdh(otherPartyPublicKey.ExportParameters());

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <see langword="true"/>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) is sensitive, cannot be read, or cannot be parsed as a named-curve uncompressed point.</exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptoPolicyViolationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        return _key.ExportEcPublicKey();
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
            "Use Pkcs11Session.ImportKey or GenerateKey instead.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException("Use Pkcs11Session.GenerateKey to generate keys on the token.");
}
