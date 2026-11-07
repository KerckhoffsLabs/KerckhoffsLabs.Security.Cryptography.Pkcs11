using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

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
    {
        // Never hand back a shared secret alongside a failure: whatever the caller's buffer held is zeroed.
        try
        {
            EncapsulateAndRead(ciphertext, sharedSecret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    private void EncapsulateAndRead(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        using SecretReadBack readBack = _key.Session.BeginReadBack(KeyMaterialExportKind.KemSharedSecret);

        var mech = new Mechanism(CKM.CKM_ML_KEM);
        using var template = ExtractableSharedSecretTemplate(Algorithm.SharedSecretSizeInBytes);
        byte[] ct = [];
        // The ML-KEM ciphertext length is fixed by the parameter set, so hand the token a pre-sized
        // buffer in one call rather than a NULL-buffer length probe (which SoftHSM does not honour). The
        // read-back owns the shared-secret key from here; the ciphertext is checked with the secret, so a
        // bad one fails the read-back (zeroing the secret and destroying the key) rather than following it.
        byte[] value = readBack.Read(
            () =>
            {
                EncapsulationResult encapsulated = _key.EncapsulateKey(mech, template, Algorithm.CiphertextSizeInBytes);
                ct = encapsulated.Ciphertext;
                return encapsulated.SharedSecret;
            },
            Algorithm.SharedSecretSizeInBytes,
            SharedSecretFailures,
            _ => RequireLength(ct, Algorithm.CiphertextSizeInBytes));
        CopyOut(value, sharedSecret);
        ct.CopyTo(ciphertext);
    }

    /// <inheritdoc/>
    /// <exception cref="CryptoPolicyViolationException">Same gating as <see cref="EncapsulateCore"/>.</exception>
    protected override void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        // Never hand back a shared secret alongside a failure: whatever the caller's buffer held is zeroed.
        try
        {
            DecapsulateAndRead(ciphertext, sharedSecret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    private void DecapsulateAndRead(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        // The private key is judged: over a long-lived key, decapsulating a recorded ciphertext returns the secret
        // DecapsulateKey kept on the token (PrivateKeyScope). Encapsulation uses no private key, so it passes none.
        using SecretReadBack readBack = _key.Session.BeginReadBack(KeyMaterialExportKind.KemSharedSecret, _key);

        var mech = new Mechanism(CKM.CKM_ML_KEM);

        // Token quirk: the decapsulated shared-secret key is created via unwrap semantics, and tokens
        // disagree on CKA_VALUE_LEN there. opencryptoki *requires* it (CKR_TEMPLATE_INCONSISTENT
        // without), while SoftHSM treats it as read-only on unwrap (CKR_ATTRIBUTE_READ_ONLY with).
        // PKCS#11 has no way to query this, so the first decapsulation against a token probes (try the
        // conventional form that includes CKA_VALUE_LEN, fall back to omitting it on SoftHSM's
        // rejection) and the answer is cached on the library — every later call goes straight to the
        // right form, so the probe's exception is one-time discovery, not steady-state control flow.
        Pkcs11Library library = _key.Session.Library;
        // A span cannot be captured; the ciphertext is public, so a copy is harmless.
        byte[] ct = ciphertext.ToArray();
        byte[] value = readBack.Read(
            () => library.MlKemDecapsulateOmitsValueLen switch
            {
                bool omit => DecapsulateWith(mech, ct, includeValueLen: !omit),
                null => DecapsulateProbing(mech, ct, library),
            },
            Algorithm.SharedSecretSizeInBytes,
            SharedSecretFailures);
        CopyOut(value, sharedSecret);
    }

    // First decapsulation against a token: try the conventional CKA_VALUE_LEN form, fall back to
    // omitting it on SoftHSM's read-only rejection, and record the winning form on the library so
    // subsequent calls skip the probe (and the failed, side-effect-free first attempt).
    private Pkcs11Key DecapsulateProbing(Mechanism mechanism, byte[] ciphertext, Pkcs11Library library)
    {
        try
        {
            Pkcs11Key sharedKey = DecapsulateWith(mechanism, ciphertext, includeValueLen: true);
            library.MlKemDecapsulateOmitsValueLen = false;
            return sharedKey;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            Pkcs11Key sharedKey = DecapsulateWith(mechanism, ciphertext, includeValueLen: false);
            library.MlKemDecapsulateOmitsValueLen = true;
            return sharedKey;
        }
    }

    // Single decapsulation attempt with a shared-secret template that optionally carries CKA_VALUE_LEN.
    private Pkcs11Key DecapsulateWith(Mechanism mechanism, byte[] ciphertext, bool includeValueLen)
    {
        using var template = ExtractableSharedSecretTemplate(Algorithm.SharedSecretSizeInBytes, includeValueLen);
        return _key.DecapsulateKey(mechanism, ciphertext, template);
    }

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

    // includeValueLen: encapsulate creates the shared secret via C_DeriveKey-style semantics
    // (CKA_VALUE_LEN is settable), but decapsulate creates it via unwrap semantics, where some tokens
    // (SoftHSM) treat CKA_VALUE_LEN as read-only and reject it (CKR_ATTRIBUTE_READ_ONLY). The ML-KEM
    // shared-secret length is fixed by the parameter set, so the token does not need to be told it —
    // omit CKA_VALUE_LEN on the decapsulate template for portability.
    private static ObjectTemplate ExtractableSharedSecretTemplate(int sharedSecretLen, bool includeValueLen = true)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .OnToken(false)
            .Sensitive(false)
            .Extractable();
        if (includeValueLen)
            builder = builder.ValueLen(sharedSecretLen);
        return builder.Build();
    }

    // How the shared-secret read-back fails: a token that would not expose the value, or a value of the
    // wrong length (which must not leave a partially-filled shared secret), and a destroy that failed
    // after a good read, which would leave an extractable copy of the secret on the token.
    private static readonly ReadBackFailures SharedSecretFailures = new(
        () => Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
            "MLKemPkcs11 (shared-secret CKA_VALUE unreadable; token rejected the extractable template)"),
        (actual, expected) => Pkcs11Exception.Create(CKR.CKR_GENERAL_ERROR,
            $"Token returned {actual}-byte shared secret; expected {expected} bytes."),
        ex => Pkcs11Exception.Create(ex.ReturnValue,
            "MLKemPkcs11: C_DestroyObject failed for the extracted shared-secret object — an " +
            "extractable copy of the shared secret may remain on-token and must be destroyed manually"));

    // Copies the read-back value into the caller's span and zeroes the managed copy.
    private static void CopyOut(byte[] value, Span<byte> destination)
    {
        try
        {
            value.CopyTo(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static void RequireLength(byte[] source, int expectedLength)
    {
        if (source.Length != expectedLength)
            throw Pkcs11Exception.Create(CKR.CKR_GENERAL_ERROR,
                $"Token returned {source.Length}-byte buffer; expected {expectedLength} bytes for this parameter set.");
    }
}
