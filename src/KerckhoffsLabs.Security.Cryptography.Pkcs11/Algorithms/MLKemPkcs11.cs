using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

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
/// <see cref="Pkcs11Key.EncapsulateKey(Mechanism, Objects.ObjectTemplate, int)"/> / <see cref="Pkcs11Key.DecapsulateKey(Mechanism, ReadOnlySpan{byte}, Objects.ObjectTemplate)"/> directly —
/// they return a <see cref="Pkcs11Key"/> wrapping the token-resident secret with no
/// extraction step.</para>
/// <para><b>Gating:</b> <see cref="EncapsulateCore(Span{byte}, Span{byte})"/> /
/// <see cref="DecapsulateCore(ReadOnlySpan{byte}, Span{byte})"/> throw
/// <see cref="CryptoPolicyViolationException"/> unless the owning session's
/// <see cref="Pkcs11Session.Policy"/> allows reading the shared secret off the token
/// (<see cref="KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportKind.KemSharedSecret"/>). Every built-in policy refuses it; opt in with
/// <c>WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([KeyMaterialExportKind.KemSharedSecret], "reason", privateKeys: PrivateKeyScope.SessionObjects))</c>
/// (reported as KLPKCS11012; the scope says which keys the secret may come from, see
/// <see cref="KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportRule.Allow"/>), applied as a scoped
/// <c>Pkcs11Session.UsePolicy</c> lease around the call or on a session of its own, not as a session\'s base policy.
/// A <c>UsePolicy(CryptoPolicy.AllowInsecure)</c> lease also allows it, but lifts every other rule and is refused on <c>NistApproved</c> sessions.
/// The gate is mechanism-agnostic — it gates the extract-and-destroy pattern itself, not <c>CKM_ML_KEM</c>.</para>
/// <para><b>Private-key export</b> (<c>ExportDecapsulationKey</c>, seed, PKCS#8) is always
/// refused. Public-key (<i>encapsulation key</i>) export reads <c>CKA_VALUE</c> from the
/// public handle.</para>
/// </remarks>
/// <remarks>
/// Wraps a PKCS#11 ML-KEM key as a BCL <see cref="MLKem"/> instance. Does not take
/// ownership.
/// </remarks>
/// <param name="key">A token-resident ML-KEM key (<see cref="CKK.CKK_ML_KEM"/>).</param>
/// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
/// <exception cref="ArgumentException"><paramref name="key"/> is not an ML-KEM key, or its parameter set is unrecognized / unreadable.</exception>
public sealed class MLKemPkcs11(Pkcs11Key key) : MLKem(ResolveAlgorithm(key))
{
    private readonly Pkcs11Key _key = key;

    // -----------------------------------------------------------------------
    // Encapsulate / decapsulate — extract-and-destroy
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the owning session's <see cref="Pkcs11Session.Policy"/> allows
    /// <see cref="KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportKind.KemSharedSecret"/>. Every built-in policy refuses it; opt in with
    /// <c>WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([KeyMaterialExportKind.KemSharedSecret], "reason", privateKeys: PrivateKeyScope.SessionObjects))</c>
    /// (reported as KLPKCS11012; the scope says which keys the secret may come from, see
    /// <see cref="KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportRule.Allow"/>), applied as a scoped
    /// <c>Pkcs11Session.UsePolicy</c> lease around the call or on a session of its own, not as a session\'s base policy.
    /// A <c>UsePolicy(CryptoPolicy.AllowInsecure)</c> lease also allows it, but lifts every other rule and is refused on <c>NistApproved</c> sessions. Or use
    /// <see cref="Pkcs11Key.EncapsulateKey(Mechanism, Objects.ObjectTemplate, int)"/> for the on-token-only path.
    /// </exception>
    protected override void EncapsulateCore(Span<byte> ciphertext, Span<byte> sharedSecret)
        // The core reads the secret back under the export rule and zeroes sharedSecret on any failure.
        => _key.EncapsulateSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sharedSecret);

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Same gating as <see cref="EncapsulateCore"/>.</exception>
    protected override void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        => _key.DecapsulateSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sharedSecret);

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Reads <c>CKA_VALUE</c> from the public handle — the FIPS 203 standard encapsulation-key encoding.</remarks>
    /// <exception cref="Pkcs11Exception">No public-key object, <c>CKA_VALUE</c> is sensitive, or the token returned a length other than the parameter set's.</exception>
    protected override void ExportEncapsulationKeyCore(Span<byte> destination)
        // Read from the public-key object only, and length-checked against the parameter set: see
        // Pkcs11Key.Export.
        => _key.Export(Pkcs11KeyBlobFormat.RawPublicKey).CopyTo(destination);

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

        ulong parameterSet = attrs[0].GetValueAsUlong();
        return PostQuantumParameterSets.AlgorithmOf<MLKemAlgorithm>(CKK.CKK_ML_KEM, parameterSet)
            ?? throw new ArgumentException($"Unrecognized ML-KEM parameter set 0x{parameterSet:X}.", nameof(key));
    }
}
