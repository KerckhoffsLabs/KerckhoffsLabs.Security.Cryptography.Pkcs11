using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// BCL-aligned RSA provider backed by a PKCS#11 <c>Pkcs11Key</c>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="RSA"/> so callers can pass this instance anywhere a BCL
/// <c>RSA</c> is accepted (e.g. <c>RSACertificateExtensions</c>, ASP.NET Core signing).
/// </para>
/// <para>
/// The BCL dispatch chain for the non-virtual <c>SignData(byte[], ...)</c> and
/// <c>VerifyData(byte[], ...)</c> overloads ultimately calls the virtual
/// <c>TrySignData</c> and <c>VerifyData(ReadOnlySpan, ...)</c> overloads, which
/// this class overrides. The full data bytes are therefore forwarded to PKCS#11 intact,
/// allowing the token to perform hashing + signing in a single <c>C_Sign</c> call using
/// the combined mechanism (e.g. <c>CKM_SHA256_RSA_PKCS</c>). This avoids using the
/// blocked <c>CKM_RSA_PKCS</c> raw-sign mechanism.
/// </para>
/// </remarks>
public sealed class RSAPkcs11 : RSA
{
    private readonly Pkcs11Key _key;

    public RSAPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_RSA)
            throw new ArgumentException(
                $"Expected an RSA key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    // -----------------------------------------------------------------------
    // Signing — forward full data to PKCS#11 using combined hash+sign mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Overrides the virtual span entry-point so the BCL non-virtual
    /// <c>SignData(byte[], HashAlgorithmName, RSASignaturePadding)</c> dispatches here
    /// with the complete, un-hashed data. The PKCS#11 mechanism performs hashing
    /// on-token (e.g. <c>CKM_SHA256_RSA_PKCS</c> for PKCS#1 / SHA-256).
    /// </remarks>
    public override bool TrySignData(
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding,
        out int bytesWritten)
    {
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = SignMechanismFor(hashAlgorithm, padding);
        byte[] sig = _key.Sign(mech, data);
        if (sig.Length > destination.Length)
        {
            bytesWritten = 0;
            return false;
        }
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
    /// <c>VerifyData(byte[], byte[], HashAlgorithmName, RSASignaturePadding)</c>
    /// dispatches here with the complete, un-hashed data.
    /// </remarks>
    public override bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Verify(mech, data, signature);
    }

    // -----------------------------------------------------------------------
    // Encryption / decryption
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = EncryptMechanismFor(padding);
        return _key.Encrypt(mech, data);
    }

    /// <inheritdoc/>
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = EncryptMechanismFor(padding);
        return _key.Decrypt(mech, data);
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <c>true</c>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export RSA private parameters. PKCS#11 keys are non-extractable " +
                "by design; export only public material via ExportParameters(false).");

        // Fast path: key was opened from a private-only token object whose public params
        // were synthesized from readable attributes on the private-key object.
        var synth = _key.GetSynthesizedRsaParameters();
        if (synth is not null) return synth.Value;

        // Normal path: key has a real CKO_PUBLIC_KEY companion — read its attributes.
        if (!_key.PublicHandle.IsInvalid)
        {
            var session = _key.Workspace.Session;
            var attrs = session.GetAttributeValue(_key.PublicHandle, new List<CKA>
            {
                CKA.CKA_MODULUS,
                CKA.CKA_PUBLIC_EXPONENT,
            });
            try
            {
                if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                    throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                        "RSAPkcs11.ExportParameters (CKA_MODULUS / CKA_PUBLIC_EXPONENT)");

                return new RSAParameters
                {
                    Modulus = attrs[0].GetValueAsByteArray(),
                    Exponent = attrs[1].GetValueAsByteArray(),
                };
            }
            finally
            {
                foreach (var a in attrs) a.Dispose();
            }
        }

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "RSAPkcs11.ExportParameters (no public material reachable)");
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(RSAParameters parameters)
        => throw new NotSupportedException(
            "RSAPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Workspace.ImportKey or GenerateKey instead.");

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Maps a BCL hash + signature padding to a PKCS#11 mechanism that hashes and signs
    /// in one shot on the token. This avoids using the insecure-by-default
    /// <c>CKM_RSA_PKCS</c> raw-sign mechanism.
    /// </summary>
    private static Mechanism SignMechanismFor(HashAlgorithmName hash, RSASignaturePadding padding)
    {
        // CKM_SHA*_RSA_PKCS is intentionally not gated: Bleichenbacher applies to PKCS#1 v1.5
        // *encryption*, not combined hash-and-sign; these mechanisms are widely deployed (JWT RS256 etc.)
        // and are left available for interop. Prefer PSS for new code.
        if (padding == RSASignaturePadding.Pkcs1)
            return Pkcs11MechanismMap.RsaPkcs1Sign(hash);
        if (padding.Mode == RSASignaturePaddingMode.Pss)
            return Pkcs11MechanismMap.RsaPssSign(hash, saltLength: -1);
        throw new NotSupportedException($"Unsupported RSA signature padding: {padding}.");
    }

    private static Mechanism EncryptMechanismFor(RSAEncryptionPadding padding)
    {
        // CKM_RSA_PKCS is gated by Session.GuardMechanism — Encrypt/Decrypt will throw
        // InsecureOperationException unless the caller opts in via AllowInsecure.
        if (padding == RSAEncryptionPadding.Pkcs1)
            return new Mechanism(CKM.CKM_RSA_PKCS);
        if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            return Pkcs11MechanismMap.RsaOaep(padding.OaepHashAlgorithm);
        throw new NotSupportedException($"Unsupported RSA encryption padding: {padding}.");
    }
}
