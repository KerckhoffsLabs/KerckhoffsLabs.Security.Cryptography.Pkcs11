using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned RSA provider backed by a PKCS#11 <c>Pkcs11Key</c>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="RSA"/> so callers can pass this instance anywhere a BCL
/// <c>RSA</c> is accepted (e.g. <c>RSACertificateExtensions</c>, ASP.NET Core signing).
/// </para>
/// <para>
/// On .NET 10, the BCL splits its sign/verify dispatch by entry-point overload:
/// the <c>byte[]</c> path goes through <c>SignData(byte[], int, int, …)</c> /
/// <c>VerifyData(byte[], int, int, byte[], …)</c>, while the span path goes through
/// <c>TrySignData(ReadOnlySpan, …)</c> / <c>VerifyData(ReadOnlySpan, ReadOnlySpan, …)</c>.
/// Neither path routes through the other, so we override both. All overrides forward
/// the full data bytes to PKCS#11 via the combined hash+sign mechanism (e.g.
/// <c>CKM_SHA256_RSA_PKCS</c>) — the token hashes and signs in a single <c>C_Sign</c> call,
/// avoiding the gated <c>CKM_RSA_PKCS</c> raw-sign mechanism.
/// </para>
/// </remarks>
public sealed class RSAPkcs11 : RSA
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a PKCS#11 RSA key as a BCL <see cref="RSA"/> instance. Does not take
    /// ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_RSA"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an RSA key.</exception>
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
    /// Span entry-point — the .NET 10 BCL routes <c>SignData(ReadOnlySpan&lt;byte&gt;, …)</c>
    /// here. The full un-hashed data is forwarded to PKCS#11; the token hashes and signs
    /// in one <c>C_Sign</c> call.
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

    /// <inheritdoc/>
    /// <remarks>
    /// Byte-array entry-point — the .NET 10 BCL routes <c>SignData(byte[], …)</c> through
    /// here, NOT through <see cref="TrySignData"/>. Without this override the default
    /// implementation calls the unimplemented <c>SignHash(byte[], …)</c> and throws
    /// <see cref="NotImplementedException"/>.
    /// </remarks>
    public override byte[] SignData(
        byte[] data,
        int offset,
        int count,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        if (offset < 0 || count < 0 || offset > data.Length - count)
            throw new ArgumentOutOfRangeException(nameof(offset));

        using var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Sign(mech, data.AsSpan(offset, count));
    }

    // -----------------------------------------------------------------------
    // Verification — forward full data to PKCS#11 using combined hash+verify mechanism
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>
    /// Span entry-point — the .NET 10 BCL routes <c>VerifyData(ReadOnlySpan, ReadOnlySpan, …)</c>
    /// here.
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

    /// <inheritdoc/>
    /// <remarks>
    /// Byte-array entry-point — the .NET 10 BCL routes
    /// <c>VerifyData(byte[], byte[], …)</c> through here, NOT through the span overload.
    /// </remarks>
    public override bool VerifyData(
        byte[] data,
        int offset,
        int count,
        byte[] signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(padding);
        if (offset < 0 || count < 0 || offset > data.Length - count)
            throw new ArgumentOutOfRangeException(nameof(offset));

        using var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Verify(mech, data.AsSpan(offset, count), signature);
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

        // Pkcs11Key.GetAttributeValue picks the public-key handle for asymmetric keys when one
        // exists, falling back to the private-key handle otherwise — covering both real key-pair
        // companions and private-only objects whose CKA_MODULUS / CKA_PUBLIC_EXPONENT are readable.
        var attrs = _key.GetAttributeValue(CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT);
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
        // Policy (see Pkcs11Session.GuardMechanism and the README "Security model" section):
        // strong-hash (SHA-2/SHA-3) RSASSA-PKCS1-v1_5 *signatures* are allowed by default. The
        // AllowInsecure gate targets broken *hashes* (MD2/MD5/SHA-1/RIPEMD — rejected in every
        // context, RsaPkcs1Sign won't map them) and PKCS#1 v1.5 *encryption* / raw RSA, not v1.5
        // signing with a strong hash. The latter remains FIPS 186-5-approved and is mandated by
        // ubiquitous interop (JWT RS256, TLS 1.2 CertificateVerify, X.509, code signing). Prefer
        // PSS for new code, but do not require an insecure opt-in for a secure, standard scheme.
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
