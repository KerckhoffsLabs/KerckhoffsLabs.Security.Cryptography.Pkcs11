using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned ML-KEM (FIPS 203) provider backed by a PKCS#11 <see cref="Pkcs11Key"/>.
/// Does NOT take ownership of the underlying key.
/// </summary>
/// <remarks>
/// <para>
/// This adapter bridges the BCL <see cref="MLKem"/> contract — which produces raw
/// shared-secret bytes — to PKCS#11 v3.2's <c>C_EncapsulateKey</c> / <c>C_DecapsulateKey</c>,
/// which produce a token-resident shared-secret <em>object</em>. Bridging the two unavoidably
/// extracts the shared-secret bytes from the token. Use this class only when the BCL
/// contract is required (e.g. feeding HKDF off-token for TLS 1.3 hybrid KEM).
/// </para>
/// <para><b>Recommended alternative:</b> when the shared secret can stay on-token, use
/// <see cref="Pkcs11Key.EncapsulateKey"/> / <see cref="Pkcs11Key.DecapsulateKey"/> directly —
/// they return a <see cref="Pkcs11Key"/> wrapping the token-resident secret with no
/// extraction step.</para>
/// <para><b>Gating:</b> <see cref="EncapsulateCore(Span{byte}, Span{byte})"/> /
/// <see cref="DecapsulateCore(ReadOnlySpan{byte}, Span{byte})"/> go through
/// <see cref="Pkcs11Key.EncapsulateAndExportSecret"/> / <see cref="Pkcs11Key.DecapsulateAndExportSecret"/>,
/// which throw <see cref="CryptoPolicyViolationException"/> unless the owning workspace's
/// <see cref="Pkcs11Workspace.Policy"/> permits the export (e.g.
/// <c>CryptoPolicy.Recommended.ToBuilder(...).AllowSecretExport(SecretExportKind.KemSharedSecret, reason)</c>).</para>
/// <para><b>Private-key export</b> (<c>ExportDecapsulationKey</c>, seed, PKCS#8) is always
/// refused. Public-key (<i>encapsulation key</i>) export reads <c>CKA_VALUE</c> from the
/// public handle.</para>
/// </remarks>
/// <remarks>
/// Wraps a PKCS#11 ML-KEM key as a BCL <see cref="MLKem"/> instance. Does not take
/// ownership.
/// </remarks>
/// <param name="key">A token-resident ML-KEM key (<see cref="CKK.CKK_ML_KEM"/>).</param>
/// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
/// <exception cref="ArgumentException"><paramref name="key"/> is not an ML-KEM key, or its parameter set is unrecognized / unreadable.</exception>
public sealed class MLKemPkcs11(Pkcs11Key key) : MLKem(ResolveAlgorithm(key))
{
    private readonly Pkcs11Key _key = key;

    // -----------------------------------------------------------------------
    // Encapsulate / decapsulate — extract-and-destroy
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the owning workspace's <see cref="Pkcs11Workspace.Policy"/> permits it.
    /// Use a policy such as
    /// <c>CryptoPolicy.Recommended.ToBuilder(...).AllowSecretExport(SecretExportKind.KemSharedSecret, reason)</c>
    /// to acknowledge that the shared secret will be extracted from the token, or use
    /// <see cref="Pkcs11Key.EncapsulateKey"/> for the on-token-only path.
    /// </exception>
    /// <exception cref="CryptographicException">The token did not expose the shared secret, or returned a ciphertext or secret of the wrong length.</exception>
    protected override void EncapsulateCore(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        // The ML-KEM ciphertext length is fixed by the parameter set, and the BCL hands over a buffer
        // of exactly that size, so the token fills it in one call.
        // The KEM read-back is experimental because its PKCS#11 shape may still move; this adapter's own
        // shape is the BCL's MLKem, which does not change with it.
#pragma warning disable KLPKCS11501
        int written = _key.EncapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sharedSecret);
#pragma warning restore KLPKCS11501
        if (written != Algorithm.CiphertextSizeInBytes)
        {
            // Never hand back a shared secret alongside a failure.
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw new CryptographicException(
                $"The token returned a {written}-byte ciphertext; this parameter set uses {Algorithm.CiphertextSizeInBytes}.");
        }
    }

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Same gating as <see cref="EncapsulateCore"/>.</exception>
    /// <exception cref="CryptographicException">The token did not expose the shared secret, or returned one of the wrong length.</exception>
#pragma warning disable KLPKCS11501 // See EncapsulateCore.
    protected override void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) =>
        _key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sharedSecret);
#pragma warning restore KLPKCS11501

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Reads <c>CKA_VALUE</c> from the public handle — the FIPS 203 standard encapsulation-key encoding.</remarks>
    /// <exception cref="CryptographicException">The token does not expose <c>CKA_VALUE</c>, or it has the wrong length.</exception>
    protected override void ExportEncapsulationKeyCore(Span<byte> destination)
    {
        using var attrs = _key.GetAttributeValue(CKA.CKA_VALUE);
        if (attrs[0].CannotBeRead)
            throw new CryptographicException("The token does not expose this key's encapsulation key (CKA_VALUE).");

        byte[] value = attrs[0].GetValueAsByteArray();
        CopyExact(value, destination, Algorithm.EncapsulationKeySizeInBytes);
    }

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Always thrown. PKCS#11 keys are non-extractable.</exception>
    protected override void ExportDecapsulationKeyCore(Span<byte> destination)
        => throw new CryptoPolicyViolationException(
            "Refusing to export ML-KEM decapsulation key bytes. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Always thrown.</exception>
    protected override void ExportPrivateSeedCore(Span<byte> destination)
        => throw new CryptoPolicyViolationException(
            "Refusing to export ML-KEM private seed. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Always thrown.</exception>
    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        => throw new CryptoPolicyViolationException(
            "Refusing to export ML-KEM decapsulation key as PKCS#8. PKCS#11 keys are non-extractable by design.");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static MLKemAlgorithm ResolveAlgorithm(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_ML_KEM)
            throw new ArgumentException(
                $"Expected an ML-KEM key, got {key.KeyType}.", nameof(key));

        using var attrs = key.GetAttributeValue(CKA.CKA_PARAMETER_SET);
        if (attrs[0].CannotBeRead)
            throw new ArgumentException(
                "ML-KEM key's CKA_PARAMETER_SET is not readable.", nameof(key));

        return (CkpMlKem)attrs[0].GetValueAsUlong() switch
        {
            CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
            CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
            CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
            var unknown => throw new ArgumentException(
                $"Unrecognized ML-KEM parameter set 0x{(ulong)unknown:X}.", nameof(key)),
        };
    }

    private static void CopyExact(byte[] source, Span<byte> destination, int expectedLength)
    {
        if (source.Length != expectedLength)
            throw new CryptographicException(
                $"The token returned {source.Length} bytes; this parameter set uses {expectedLength}.");
        source.CopyTo(destination);
    }
}
