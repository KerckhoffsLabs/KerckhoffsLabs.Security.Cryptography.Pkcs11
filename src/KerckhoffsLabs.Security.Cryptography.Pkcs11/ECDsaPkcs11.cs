using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

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
    public override bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        var session = _key.Workspace.Session;
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (session.SupportsMechanism((CKM)combined.Type))
        {
            return _key.Verify(combined, data, signature);
        }
        combined.Dispose();
        byte[] hash = HashData(hashAlgorithm, data);
        using var raw = new Mechanism(CKM.CKM_ECDSA);
        return _key.Verify(raw, hash, signature);
    }

    // -----------------------------------------------------------------------
    // Sign/verify hash — raw ECDSA (no on-token hashing)
    // ECDsa.SignHash(byte[]) and VerifyHash(byte[], byte[]) are abstract in the BCL;
    // the byte[] overloads must be implemented directly.
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(mech, hash);
    }

    /// <inheritdoc/>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Verify(mech, hash, signature);
    }

    private byte[] SignDataInternal(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        var session = _key.Workspace.Session;
        var combined = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        if (session.SupportsMechanism((CKM)combined.Type))
            return _key.Sign(combined, data);
        combined.Dispose();
        byte[] hash = HashData(hashAlgorithm, data);
        using var raw = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(raw, hash);
    }

    private static byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data) =>
        hashAlgorithm.Name switch
        {
            "SHA1" => System.Security.Cryptography.SHA1.HashData(data),
            "SHA256" => System.Security.Cryptography.SHA256.HashData(data),
            "SHA384" => System.Security.Cryptography.SHA384.HashData(data),
            "SHA512" => System.Security.Cryptography.SHA512.HashData(data),
            _ => throw new NotSupportedException($"ECDSA does not support hash {hashAlgorithm.Name}.")
        };

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

        // Path 1: private-only key with CKA_EC_POINT stored on the private object.
        var synth = _key.GetSynthesizedEcParameters();
        if (synth is not null) return synth.Value;

        // Path 2: key pair generated via GenerateKey — read CKA_EC_POINT + CKA_EC_PARAMS
        // from the real public-key companion handle.
        if (!_key.PublicHandle.IsInvalid)
        {
            var fromPublic = Pkcs11PublicKeyView.TrySynthesizeEc(
                _key.Workspace.Session, _key.PublicHandle);
            if (fromPublic is not null) return fromPublic.Value;
        }

        throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
            "ECDsaPkcs11.ExportParameters (CKA_EC_POINT / CKA_EC_PARAMS could not be read from any available handle)");
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
