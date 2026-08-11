using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

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
/// The BCL dispatch chain for the non-virtual <c>SignData(byte[], HashAlgorithmName)</c> and
/// <c>VerifyData(byte[], byte[], HashAlgorithmName)</c> overloads ultimately calls the virtual
/// <c>TrySignData</c> and <c>VerifyData(ReadOnlySpan, ...)</c> overloads, which
/// this class overrides. The full data bytes are therefore forwarded to PKCS#11 intact,
/// allowing the token to perform hashing + signing in a single <c>C_Sign</c> call using
/// the combined mechanism (e.g. <c>CKM_ECDSA_SHA256</c>). This avoids pre-hashing on the
/// managed side.
/// </para>
/// </remarks>
public sealed class ECDsaPkcs11 : ECDsa
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a PKCS#11 EC key as a BCL <see cref="ECDsa"/> instance. Does not take
    /// ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_EC"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an EC key.</exception>
    public ECDsaPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_EC)
            throw new ArgumentException(
                $"Expected an EC key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    // -----------------------------------------------------------------------
    // Signing — forward full data to PKCS#11 using combined hash+sign mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Overrides the virtual span entry-point so the BCL non-virtual
    /// <c>SignData(byte[], HashAlgorithmName)</c> dispatches here with the complete,
    /// un-hashed data. The PKCS#11 mechanism performs hashing on-token
    /// (e.g. <c>CKM_ECDSA_SHA256</c> for SHA-256).
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/256/384/512.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <paramref name="hashAlgorithm"/> is SHA-1 unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set.</exception>
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
    /// Overrides the virtual span entry-point so the BCL non-virtual
    /// <c>VerifyData(byte[], byte[], HashAlgorithmName)</c> dispatches here with the
    /// complete, un-hashed data.
    /// </remarks>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/256/384/512.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <paramref name="hashAlgorithm"/> is SHA-1 unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (_key.SupportsMechanism((CKM)combined.Type))
        {
            return _key.Verify(combined, data, signature);
        }
        byte[] hash = HashData(hashAlgorithm, data);
        var raw = new Mechanism(CKM.CKM_ECDSA);
        return _key.Verify(raw, hash, signature);
    }

    // -----------------------------------------------------------------------
    // Sign/verify hash — raw ECDSA (no on-token hashing)
    // ECDsa.SignHash(byte[]) and VerifyHash(byte[], byte[]) are abstract in the BCL;
    // the byte[] overloads must be implemented directly.
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Signs the caller-supplied digest with raw <c>CKM_ECDSA</c>. The hash algorithm is not
    /// conveyed on this path, so the SHA-1 secure-defaults gate does not apply here.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="hash"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(mech, hash);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="hash"/> or <paramref name="signature"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Verify(mech, hash, signature);
    }

    private byte[] SignDataInternal(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (_key.SupportsMechanism((CKM)combined.Type))
            return _key.Sign(combined, data);
        byte[] hash = HashData(hashAlgorithm, data);
        var raw = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(raw, hash);
    }

    // Refuse SHA-1 unless the workspace opts in via AllowInsecure, mirroring GuardMechanism's rejection
    // of the combined CKM_ECDSA_SHA1 mechanism. Gating here (the managed-side pre-hash) closes the gap
    // for tokens that lack the combined mechanism. SHA-1 is gated on every entry point that knows the
    // hash algorithm — the BCL byte[]/Stream SignData/VerifyData overloads pre-hash through the
    // protected HashData overrides below, the span overloads through the private hasher. SignHash /
    // VerifyHash(byte[]) sign caller-supplied digest bytes and cannot know the algorithm, so they are
    // inherently outside this gate.
    private void GuardWeakHash(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm.Name == "SHA1" && !_key.Workspace.AllowInsecure)
            throw new InsecureOperationException(
                "SHA-1 is collision-broken and deprecated in signature contexts. Set Pkcs11Workspace.AllowInsecure " +
                "to opt in (e.g. to verify a legacy signature), or use SHA-256 or stronger.");
    }

    /// <inheritdoc/>
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        GuardWeakHash(hashAlgorithm);
        return base.HashData(data, offset, count, hashAlgorithm);
    }

    /// <inheritdoc/>
    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        GuardWeakHash(hashAlgorithm);
        return base.HashData(data, hashAlgorithm);
    }

    private byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data)
    {
        GuardWeakHash(hashAlgorithm);
        return hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.HashData(data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"ECDSA does not support hash {hashAlgorithm.Name}.")
        };
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <c>true</c>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Thrown when the public point (<c>CKA_EC_POINT</c> / <c>CKA_EC_PARAMS</c>) is sensitive, cannot be read from any available handle, or cannot be parsed as a named-curve uncompressed point.</exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        // Pkcs11Key.GetAttributeValue picks the public-key handle for asymmetric keys when one
        // exists and falls back to the private-key handle otherwise — covering both real key-pair
        // companions and private-only objects that carry CKA_EC_POINT / CKA_EC_PARAMS.
        using var attrs = _key.GetAttributeValue(CKA.CKA_EC_POINT, CKA.CKA_EC_PARAMS);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                "ECDsaPkcs11.ExportParameters (CKA_EC_POINT / CKA_EC_PARAMS not readable from any available handle)");

        var ec = Pkcs11PublicKeyView.TryParseEcPublicKey(
            attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
        return ec ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
            "ECDsaPkcs11.ExportParameters (CKA_EC_POINT / CKA_EC_PARAMS could not be parsed as a named-curve uncompressed point)");
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
            "Use Pkcs11Workspace.ImportKey or GenerateKey instead.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException(
            "Use Pkcs11Workspace.GenerateKey to generate keys on the token.");
}
