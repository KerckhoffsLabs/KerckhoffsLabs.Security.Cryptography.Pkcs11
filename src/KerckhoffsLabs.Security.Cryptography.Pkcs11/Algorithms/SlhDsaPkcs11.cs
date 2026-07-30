using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

// SlhDsa (FIPS 205) is an evaluation-only BCL type in .NET 10 (SYSLIB5006), so this adapter is itself
// marked [Experimental("SYSLIB5006")] (see the class) to propagate that status to its consumers —
// exactly as the BCL marks SlhDsa. (MLDsa and MLKem were stabilized in .NET 10, so MLDsaPkcs11 /
// MLKemPkcs11 are not marked.) The file-scoped pragma below suppresses the diagnostic for this
// adapter's own internal use of the experimental SlhDsa type.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned SLH-DSA (FIPS 205) provider backed by a PKCS#11 <see cref="Pkcs11Key"/>.
/// Does NOT take ownership of the underlying key.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="SlhDsa"/> so callers can pass this instance anywhere a BCL
/// <c>SlhDsa</c> is accepted. The parameter set (one of the twelve SLH-DSA-SHA2 / SHAKE,
/// 128/192/256, s/f variants) is discovered from the token by reading
/// <c>CKA_PARAMETER_SET</c> on a reachable handle.
/// </para>
/// <para>
/// Signing forwards to <c>CKM_SLH_DSA</c>; the token performs the actual signature operation
/// on the non-extractable private key. Pre-hash mode (<c>HashSLH-DSA</c>) is not supported
/// because PKCS#11 v3.2's <c>CKM_HASH_SLH_DSA_*</c> mechanisms hash their own input rather than
/// accepting a caller-supplied digest.
/// </para>
/// <para>
/// Private-key export (raw key bytes, PKCS#8) is refused: PKCS#11 keys are non-extractable by
/// design. Public-key export reads <c>CKA_VALUE</c> from the public handle, which holds the
/// FIPS 205 standard public-key encoding.
/// </para>
/// </remarks>
/// <param name="key">A token-resident SLH-DSA key (<see cref="CKK.CKK_SLH_DSA"/>).</param>
/// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
/// <exception cref="ArgumentException"><paramref name="key"/> is not an SLH-DSA key, or its parameter set is unrecognized / unreadable.</exception>
[Experimental("SYSLIB5006", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
public sealed class SlhDsaPkcs11(Pkcs11Key key) : SlhDsa(ResolveAlgorithm(key))
{
    private readonly Pkcs11Key _key = key;

    // -----------------------------------------------------------------------
    // Sign / verify — pure SLH-DSA (CKM_SLH_DSA)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    protected override void SignDataCore(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> context,
        Span<byte> destination)
    {
        if (context.Length > 255)
            throw new ArgumentException("SLH-DSA context must be at most 255 bytes.", nameof(context));

        var mech = Pkcs11MechanismMap.SlhDsaSign(context: context);
        byte[] sig = _key.Sign(mech, data);
        CopyExact(sig, destination, Algorithm.SignatureSizeInBytes);
    }

    /// <inheritdoc/>
    protected override bool VerifyDataCore(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> context,
        ReadOnlySpan<byte> signature)
    {
        if (context.Length > 255)
            throw new ArgumentException("SLH-DSA context must be at most 255 bytes.", nameof(context));

        var mech = Pkcs11MechanismMap.SlhDsaSign(context: context);
        return _key.Verify(mech, data, signature);
    }

    // -----------------------------------------------------------------------
    // Sign / verify — HashSLH-DSA — not implementable on PKCS#11 v3.2
    // -----------------------------------------------------------------------
    //
    // The BCL SignPreHash / VerifyPreHash contracts pass the pre-computed digest of the
    // message; the implementation is expected to produce / verify a HashSLH-DSA signature
    // (FIPS 205 §10.2.2) over that digest. PKCS#11 v3.2's CKM_HASH_SLH_DSA_<H> takes the
    // MESSAGE and hashes it internally, so feeding it the caller's pre-computed hash would
    // sign H(H(M)) and interoperate with nothing; CKM_SLH_DSA uses the 0x00 (pure) domain
    // prefix, never 0x01 (HashSLH-DSA). No mechanism accepts a caller-supplied pre-hash, so
    // throw rather than silently produce non-interoperable signatures.

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Always thrown. PKCS#11 v3.2 has no mechanism that accepts a caller-supplied
    /// pre-hash for HashSLH-DSA; <c>CKM_HASH_SLH_DSA_*</c> hashes its own input.
    /// </exception>
    protected override void SignPreHashCore(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> context,
        string hashAlgorithmOid,
        Span<byte> destination)
        => throw new NotSupportedException(
            "HashSLH-DSA pre-hash signing is not supported by PKCS#11 v3.2: " +
            "CKM_HASH_SLH_DSA_* hashes its own input, and CKM_SLH_DSA uses the 0x00 (pure) " +
            "domain prefix rather than 0x01 (HashSLH-DSA). " +
            "Use SignData(message, context) with CKM_SLH_DSA instead, or sign the digest " +
            "with another HashSLH-DSA implementation.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown. See <see cref="SignPreHashCore"/>.</exception>
    protected override bool VerifyPreHashCore(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> context,
        string hashAlgorithmOid,
        ReadOnlySpan<byte> signature)
        => throw new NotSupportedException(
            "HashSLH-DSA pre-hash verification is not supported by PKCS#11 v3.2. " +
            "See SignPreHashCore for details.");

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Reads <c>CKA_VALUE</c> from the public-key handle (FIPS 205 standard public-key encoding).</remarks>
    /// <exception cref="Pkcs11Exception">No public handle reachable or <c>CKA_VALUE</c> is sensitive.</exception>
    protected override void ExportSlhDsaPublicKeyCore(Span<byte> destination)
    {
        var attrs = _key.GetAttributeValue(CKA.CKA_VALUE);
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "SlhDsaPkcs11.ExportSlhDsaPublicKey (CKA_VALUE unreadable)");

            byte[] value = attrs[0].GetValueAsByteArray();
            CopyExact(value, destination, Algorithm.PublicKeySizeInBytes);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown. PKCS#11 keys are non-extractable.</exception>
    protected override void ExportSlhDsaPrivateKeyCore(Span<byte> destination)
        => throw new InsecureOperationException(
            "Refusing to export SLH-DSA private key bytes. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown.</exception>
    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        => throw new InsecureOperationException(
            "Refusing to export SLH-DSA private key as PKCS#8. PKCS#11 keys are non-extractable by design.");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static SlhDsaAlgorithm ResolveAlgorithm(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_SLH_DSA)
            throw new ArgumentException(
                $"Expected an SLH-DSA key, got {key.KeyType}.", nameof(key));

        var attrs = key.GetAttributeValue(CKA.CKA_PARAMETER_SET);
        try
        {
            if (attrs[0].CannotBeRead)
                throw new ArgumentException(
                    "SLH-DSA key's CKA_PARAMETER_SET is not readable.", nameof(key));

            return (CkpSlhDsa)attrs[0].GetValueAsUlong() switch
            {
                CkpSlhDsa.CKP_SLH_DSA_SHA2_128S => SlhDsaAlgorithm.SlhDsaSha2_128s,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S => SlhDsaAlgorithm.SlhDsaShake128s,
                CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => SlhDsaAlgorithm.SlhDsaSha2_128f,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => SlhDsaAlgorithm.SlhDsaShake128f,
                CkpSlhDsa.CKP_SLH_DSA_SHA2_192S => SlhDsaAlgorithm.SlhDsaSha2_192s,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S => SlhDsaAlgorithm.SlhDsaShake192s,
                CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => SlhDsaAlgorithm.SlhDsaSha2_192f,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F => SlhDsaAlgorithm.SlhDsaShake192f,
                CkpSlhDsa.CKP_SLH_DSA_SHA2_256S => SlhDsaAlgorithm.SlhDsaSha2_256s,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S => SlhDsaAlgorithm.SlhDsaShake256s,
                CkpSlhDsa.CKP_SLH_DSA_SHA2_256F => SlhDsaAlgorithm.SlhDsaSha2_256f,
                CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => SlhDsaAlgorithm.SlhDsaShake256f,
                var unknown => throw new ArgumentException(
                    $"Unrecognized SLH-DSA parameter set 0x{(ulong)unknown:X}.", nameof(key)),
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    private static void CopyExact(byte[] source, Span<byte> destination, int expectedLength)
    {
        if (source.Length != expectedLength)
            throw Pkcs11Exception.Create(CKR.CKR_GENERAL_ERROR,
                $"Token returned {source.Length}-byte buffer; expected {expectedLength} bytes for this parameter set.");
        source.CopyTo(destination);
    }
}
