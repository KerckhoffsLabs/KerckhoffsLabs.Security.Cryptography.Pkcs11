using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned ML-DSA (FIPS 204) provider backed by a PKCS#11 <see cref="Pkcs11Key"/>.
/// Does NOT take ownership of the underlying key.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="MLDsa"/> so callers can pass this instance anywhere a BCL
/// <c>MLDsa</c> is accepted. The parameter set (ML-DSA-44 / 65 / 87) is discovered from
/// the token by reading <c>CKA_PARAMETER_SET</c> on a reachable handle.
/// </para>
/// <para>
/// Signing forwards to <c>CKM_ML_DSA</c> (or <c>CKM_HASH_ML_DSA_*</c> for pre-hash mode);
/// the token performs the actual signature operation on the non-extractable private key.
/// External-mu sign/verify (FIPS 204 §6.2) is not supported because PKCS#11 v3.2 does not
/// define a corresponding mechanism.
/// </para>
/// <para>
/// Private-key export (raw key bytes, FIPS 204 seed, PKCS#8) is refused: PKCS#11 keys are
/// non-extractable by design. Public-key export reads <c>CKA_VALUE</c> from the public
/// handle, which holds the FIPS 204 standard public-key encoding.
/// </para>
/// </remarks>
/// <remarks>
/// Wraps a PKCS#11 ML-DSA key as a BCL <see cref="MLDsa"/> instance. Does not take
/// ownership — disposing this provider does not dispose <paramref name="key"/>.
/// </remarks>
/// <param name="key">A token-resident ML-DSA key (<see cref="CKK.CKK_ML_DSA"/>).</param>
/// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
/// <exception cref="ArgumentException"><paramref name="key"/> is not an ML-DSA key, or its parameter set is unrecognized / unreadable.</exception>
public sealed class MLDsaPkcs11(Pkcs11Key key) : MLDsa(ResolveAlgorithm(key))
{
    private readonly Pkcs11Key _key = key;

    // -----------------------------------------------------------------------
    // Sign / verify — pure ML-DSA (CKM_ML_DSA)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    protected override void SignDataCore(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> context,
        Span<byte> destination)
    {
        if (context.Length > 255)
            throw new ArgumentException("ML-DSA context must be at most 255 bytes.", nameof(context));

        using var mech = Pkcs11MechanismMap.MlDsaSign(context: context);
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
            throw new ArgumentException("ML-DSA context must be at most 255 bytes.", nameof(context));

        using var mech = Pkcs11MechanismMap.MlDsaSign(context: context);
        return _key.Verify(mech, data, signature);
    }

    // -----------------------------------------------------------------------
    // Sign / verify — HashML-DSA — not implementable on PKCS#11 v3.2
    // -----------------------------------------------------------------------
    //
    // The BCL SignPreHash / VerifyPreHash contracts pass the pre-computed digest of the
    // message; the implementation is expected to produce / verify a HashML-DSA signature
    // (FIPS 204 §5.4) over that digest. PKCS#11 v3.2 offers two relevant mechanisms:
    //
    //  - CKM_ML_DSA: signs M' = 0x00 || len(ctx) || ctx || M (pure ML-DSA with the 0x00
    //    domain prefix). Cannot produce a HashML-DSA signature because the domain
    //    prefix is structurally 0x00, never 0x01.
    //  - CKM_HASH_ML_DSA_<H>: signs M' = 0x01 || len(ctx) || ctx || OID(H) || H(M).
    //    The mechanism's input is the MESSAGE — it hashes internally. Feeding it the
    //    caller's pre-computed hash would sign H(H(M)) instead of the FIPS 204 value
    //    over the message; the resulting signature is well-formed but interoperates
    //    with nothing.
    //
    // No PKCS#11 v3.2 mechanism accepts a caller-supplied pre-hash. Throw rather than
    // silently produce non-interoperable signatures. Consumers that need HashML-DSA can
    // hash the message themselves and sign with another implementation, or — when the
    // message is available — let CKM_HASH_ML_DSA_<H> handle the full operation by
    // adding a non-virtual SignDataHashed helper here (out of scope for this fix).

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Always thrown. PKCS#11 v3.2 has no mechanism that accepts a caller-supplied
    /// pre-hash for HashML-DSA; <c>CKM_HASH_ML_DSA_*</c> hashes its own input.
    /// </exception>
    protected override void SignPreHashCore(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> context,
        string hashAlgorithmOid,
        Span<byte> destination)
        => throw new NotSupportedException(
            "HashML-DSA pre-hash signing is not supported by PKCS#11 v3.2: " +
            "CKM_HASH_ML_DSA_* hashes its own input, and CKM_ML_DSA uses the 0x00 (pure) " +
            "domain prefix rather than 0x01 (HashML-DSA). " +
            "Use SignData(message, context) with CKM_ML_DSA instead, or sign the digest " +
            "with another HashML-DSA implementation.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown. See <see cref="SignPreHashCore"/>.</exception>
    protected override bool VerifyPreHashCore(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> context,
        string hashAlgorithmOid,
        ReadOnlySpan<byte> signature)
        => throw new NotSupportedException(
            "HashML-DSA pre-hash verification is not supported by PKCS#11 v3.2. " +
            "See SignPreHashCore for details.");

    // -----------------------------------------------------------------------
    // External-mu sign / verify — not supported by PKCS#11 v3.2.
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    protected override void SignMuCore(ReadOnlySpan<byte> externalMu, Span<byte> destination)
        => throw new NotSupportedException(
            "External-mu signing (FIPS 204 §6.2) has no corresponding PKCS#11 v3.2 mechanism.");

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    protected override bool VerifyMuCore(ReadOnlySpan<byte> externalMu, ReadOnlySpan<byte> signature)
        => throw new NotSupportedException(
            "External-mu verification has no corresponding PKCS#11 v3.2 mechanism.");

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Reads <c>CKA_VALUE</c> from the public-key handle (FIPS 204 standard public-key encoding).</remarks>
    /// <exception cref="Pkcs11Exception">No public handle reachable or <c>CKA_VALUE</c> is sensitive.</exception>
    protected override void ExportMLDsaPublicKeyCore(Span<byte> destination)
    {
        var attrs = _key.GetAttributeValue(CKA.CKA_VALUE);
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "MLDsaPkcs11.ExportMLDsaPublicKey (CKA_VALUE unreadable)");

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
    protected override void ExportMLDsaPrivateKeyCore(Span<byte> destination)
        => throw new InsecureOperationException(
            "Refusing to export ML-DSA private key bytes. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown.</exception>
    protected override void ExportMLDsaPrivateSeedCore(Span<byte> destination)
        => throw new InsecureOperationException(
            "Refusing to export ML-DSA private seed. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown.</exception>
    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        => throw new InsecureOperationException(
            "Refusing to export ML-DSA private key as PKCS#8. PKCS#11 keys are non-extractable by design.");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static MLDsaAlgorithm ResolveAlgorithm(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_ML_DSA)
            throw new ArgumentException(
                $"Expected an ML-DSA key, got {key.KeyType}.", nameof(key));

        var attrs = key.GetAttributeValue(CKA.CKA_PARAMETER_SET);
        try
        {
            if (attrs[0].CannotBeRead)
                throw new ArgumentException(
                    "ML-DSA key's CKA_PARAMETER_SET is not readable.", nameof(key));

            return (CkpMlDsa)attrs[0].GetValueAsUlong() switch
            {
                CkpMlDsa.CKP_ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
                CkpMlDsa.CKP_ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
                CkpMlDsa.CKP_ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
                var unknown => throw new ArgumentException(
                    $"Unrecognized ML-DSA parameter set 0x{(ulong)unknown:X}.", nameof(key)),
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
