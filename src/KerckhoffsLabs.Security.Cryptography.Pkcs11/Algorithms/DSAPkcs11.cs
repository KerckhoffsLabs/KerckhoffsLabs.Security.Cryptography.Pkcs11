using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned DSA provider backed by a PKCS#11 <see cref="Pkcs11Key"/>. Does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="DSA"/> so callers can pass this instance anywhere a BCL <c>DSA</c> is
/// accepted. Signing forwards the full message to the combined <c>CKM_DSA_SHA*</c> mechanism so the
/// token hashes and signs in one <c>C_Sign</c> call; if the token lacks the combined mechanism it
/// falls back to hashing on the managed side and signing the digest with raw <c>CKM_DSA</c>. Both
/// produce IEEE P1363 (r‖s) signatures, matching the BCL default — the base class converts to the
/// DER format on request via the <c>DSASignatureFormat</c> overloads.
/// </para>
/// <para>
/// Note: NIST FIPS 186-5 (2023) disallows DSA for signature generation; this adapter is for interop
/// with existing DSA keys. Private-key parameter export is refused (PKCS#11 keys are non-extractable);
/// <see cref="ExportParameters(bool)"/> with <c>false</c> reads the domain parameters and public value
/// (<c>CKA_PRIME</c> / <c>CKA_SUBPRIME</c> / <c>CKA_BASE</c> / <c>CKA_VALUE</c>) from the public handle.
/// </para>
/// </remarks>
[Obsolete("DSA is disallowed for signature generation by NIST FIPS 186-5 (2023) and is removed from modern " +
          "deployments. Use ECDsaPkcs11 (ECDSA) or MLDsaPkcs11 (ML-DSA). DSAPkcs11 remains only for interop " +
          "with existing DSA keys; SHA-1 hashing additionally requires the wrapped key's Pkcs11Workspace.AllowInsecure = true.")]
public sealed class DSAPkcs11 : DSA
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a PKCS#11 DSA key as a BCL <see cref="DSA"/> instance. Does not take ownership —
    /// disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is <see cref="CKK.CKK_DSA"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not a DSA key.</exception>
    public DSAPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_DSA)
            throw new ArgumentException($"Expected a DSA key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    // -----------------------------------------------------------------------
    // Sign / verify a hash — raw CKM_DSA (P1363 r‖s)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rgbHash"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set: every <c>CKM_DSA</c> mechanism is gated because FIPS 186-5 disallows DSA signature generation.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override byte[] CreateSignature(byte[] rgbHash)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);
        using var mech = new Mechanism(CKM.CKM_DSA);
        return _key.Sign(mech, rgbHash);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rgbHash"/> or <paramref name="rgbSignature"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);
        ArgumentNullException.ThrowIfNull(rgbSignature);
        using var mech = new Mechanism(CKM.CKM_DSA);
        return _key.Verify(mech, rgbHash, rgbSignature);
    }

    // -----------------------------------------------------------------------
    // Sign / verify data — combined on-token hash+sign (CKM_DSA_SHA*)
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512.</exception>
    /// <exception cref="InsecureOperationException">Thrown unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Sign</c> call.</exception>
    public override bool TrySignData(
        ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten)
    {
        byte[] sig = SignDataInternal(data, hashAlgorithm);
        if (sig.Length > destination.Length) { bytesWritten = 0; return false; }
        sig.CopyTo(destination);
        bytesWritten = sig.Length;
        return true;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Thrown if <paramref name="hashAlgorithm"/> is not one of SHA-1/224/256/384/512.</exception>
    /// <exception cref="InsecureOperationException">Thrown unless the wrapped key's workspace has <c>Pkcs11Workspace.AllowInsecure</c> set: every <c>CKM_DSA</c> mechanism is gated.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Verify</c> call.</exception>
    public override bool VerifyData(
        ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.DsaSign(hashAlgorithm);
        if (_key.SupportsMechanism((CKM)combined.Type))
            return _key.Verify(combined, data, signature);

        combined.Dispose();
        byte[] hash = HashData(hashAlgorithm, data);
        using var raw = new Mechanism(CKM.CKM_DSA);
        return _key.Verify(raw, hash, signature);
    }

    private byte[] SignDataInternal(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        var combined = Pkcs11MechanismMap.DsaSign(hashAlgorithm);
        if (_key.SupportsMechanism((CKM)combined.Type))
            return _key.Sign(combined, data);

        combined.Dispose();
        byte[] hash = HashData(hashAlgorithm, data);
        using var raw = new Mechanism(CKM.CKM_DSA);
        return _key.Sign(raw, hash);
    }

    // No SHA-1-specific gate here: DSA is insecure as an algorithm (FIPS 186-5 disallows it), so every
    // CKM_DSA* mechanism — raw and combined, all hashes — is gated at the session layer (GuardMechanism)
    // and requires Pkcs11Workspace.AllowInsecure. A per-hash guard would be redundant.
    private static byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data) =>
        hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.HashData(data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"DSA does not support hash {hashAlgorithm.Name}."),
        };

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">
    /// Always thrown when <paramref name="includePrivateParameters"/> is <c>true</c>.
    /// PKCS#11 keys are non-extractable by design.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Thrown when the domain parameters or public value (<c>CKA_PRIME</c> / <c>CKA_SUBPRIME</c> / <c>CKA_BASE</c> / <c>CKA_VALUE</c>) are sensitive or cannot be read.</exception>
    public override DSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export DSA private key (X). PKCS#11 keys are non-extractable by design; " +
                "export only public material via ExportParameters(false).");

        // Pkcs11Key.GetAttributeValue picks the public-key handle for asymmetric keys when one exists,
        // so CKA_VALUE resolves to the public value Y (not the private value X).
        var attrs = _key.GetAttributeValue(CKA.CKA_PRIME, CKA.CKA_SUBPRIME, CKA.CKA_BASE, CKA.CKA_VALUE);
        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead || attrs[2].CannotBeRead || attrs[3].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "DSAPkcs11.ExportParameters (CKA_PRIME / CKA_SUBPRIME / CKA_BASE / CKA_VALUE)");

            byte[] p = TrimLeadingZeros(attrs[0].GetValueAsByteArray());
            byte[] q = TrimLeadingZeros(attrs[1].GetValueAsByteArray());
            return new DSAParameters
            {
                P = p,
                Q = q,
                // DSAParameters requires G and Y to share the prime length; left-pad to P.
                G = LeftPad(attrs[2].GetValueAsByteArray(), p.Length),
                Y = LeftPad(attrs[3].GetValueAsByteArray(), p.Length),
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    public override void ImportParameters(DSAParameters parameters)
        => throw new NotSupportedException(
            "DSAPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Workspace.ImportKey or GenerateKey instead.");

    private static byte[] TrimLeadingZeros(byte[] value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0) start++;
        return start == 0 ? value : value[start..];
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        value = TrimLeadingZeros(value);
        if (value.Length == length) return value;
        if (value.Length > length) return value[^length..];
        byte[] result = new byte[length];
        value.CopyTo(result, length - value.Length);
        return result;
    }
}
