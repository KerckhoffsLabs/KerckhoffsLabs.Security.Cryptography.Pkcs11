using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
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
/// <see cref="Pkcs11Key.EncapsulateKey"/> / <see cref="Pkcs11Key.DecapsulateKey"/> directly —
/// they return a <see cref="Pkcs11Key"/> wrapping the token-resident secret with no
/// extraction step.</para>
/// <para><b>Gating:</b> <see cref="EncapsulateCore(Span{byte}, Span{byte})"/> /
/// <see cref="DecapsulateCore(ReadOnlySpan{byte}, Span{byte})"/> throw
/// <see cref="InsecureOperationException"/> unless the owning workspace has set
/// <c>Pkcs11Workspace.AllowInsecure = true</c> (or <c>AllowInsecureScope()</c>). The gate is
/// mechanism-agnostic — it gates the extract-and-destroy pattern itself, not <c>CKM_ML_KEM</c>.</para>
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
    /// <exception cref="InsecureOperationException">
    /// Thrown when the owning workspace has not set <c>Pkcs11Workspace.AllowInsecure = true</c>.
    /// Set it explicitly (or scope it with <c>AllowInsecureScope()</c>) to acknowledge that the
    /// shared secret will be extracted from the token, or use <see cref="Pkcs11Key.EncapsulateKey"/>
    /// for the on-token-only path.
    /// </exception>
    protected override void EncapsulateCore(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        GuardExtraction(encapsulating: true);

        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        using var template = ExtractableSharedSecretTemplate(Algorithm.SharedSecretSizeInBytes);
        // The ML-KEM ciphertext length is fixed by the parameter set, so hand the token a pre-sized
        // buffer in one call rather than a NULL-buffer length probe (which SoftHSM does not honour).
        var (ct, sharedKey) = _key.EncapsulateKey(mech, template, Algorithm.CiphertextSizeInBytes);

        try
        {
            ReadAndCopySecret(sharedKey, sharedSecret);
            CopyExact(ct, ciphertext, Algorithm.CiphertextSizeInBytes);
            // Destroy the extracted, extractable shared-secret object now that we hold its bytes.
            // Surfaced (not swallowed): a failure here would leave the secret lingering on-token.
            DestroyExtractedSecret(sharedKey);
        }
        catch
        {
            // Never hand back a shared secret alongside a failure (copy or cleanup).
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
        finally
        {
            sharedKey.Dispose();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Same gating as <see cref="EncapsulateCore"/>.</exception>
    protected override void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        GuardExtraction(encapsulating: false);

        using var mech = new Mechanism(CKM.CKM_ML_KEM);

        // Token quirk: the decapsulated shared-secret key is created via unwrap semantics, and tokens
        // disagree on CKA_VALUE_LEN there. opencryptoki *requires* it (CKR_TEMPLATE_INCONSISTENT
        // without), while SoftHSM treats it as read-only on unwrap (CKR_ATTRIBUTE_READ_ONLY with).
        // PKCS#11 has no way to query this, so the first decapsulation against a token probes (try the
        // conventional form that includes CKA_VALUE_LEN, fall back to omitting it on SoftHSM's
        // rejection) and the answer is cached on the library — every later call goes straight to the
        // right form, so the probe's exception is one-time discovery, not steady-state control flow.
        Pkcs11Library library = _key.Workspace.Library;
        Pkcs11Key sharedKey = library.MlKemDecapsulateOmitsValueLen switch
        {
            bool omit => DecapsulateWith(mech, ciphertext, includeValueLen: !omit),
            null => DecapsulateProbing(mech, ciphertext, library),
        };

        try
        {
            ReadAndCopySecret(sharedKey, sharedSecret);
            // Surfaced (not swallowed): a destroy failure would leave the secret lingering on-token.
            DestroyExtractedSecret(sharedKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
        finally
        {
            sharedKey.Dispose();
        }
    }

    // First decapsulation against a token: try the conventional CKA_VALUE_LEN form, fall back to
    // omitting it on SoftHSM's read-only rejection, and record the winning form on the library so
    // subsequent calls skip the probe (and the failed, side-effect-free first attempt).
    private Pkcs11Key DecapsulateProbing(Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Pkcs11Library library)
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
    private Pkcs11Key DecapsulateWith(Mechanism mechanism, ReadOnlySpan<byte> ciphertext, bool includeValueLen)
    {
        using var template = ExtractableSharedSecretTemplate(Algorithm.SharedSecretSizeInBytes, includeValueLen);
        return _key.DecapsulateKey(mechanism, ciphertext, template);
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    /// <remarks>Reads <c>CKA_VALUE</c> from the public handle — the FIPS 203 standard encapsulation-key encoding.</remarks>
    /// <exception cref="Pkcs11Exception">No public handle reachable or <c>CKA_VALUE</c> is sensitive.</exception>
    protected override void ExportEncapsulationKeyCore(Span<byte> destination)
    {
        var attrs = _key.GetAttributeValue(CKA.CKA_VALUE);
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "MLKemPkcs11.ExportEncapsulationKey (CKA_VALUE unreadable)");

            byte[] value = attrs[0].GetValueAsByteArray();
            CopyExact(value, destination, Algorithm.EncapsulationKeySizeInBytes);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown. PKCS#11 keys are non-extractable.</exception>
    protected override void ExportDecapsulationKeyCore(Span<byte> destination)
        => throw new InsecureOperationException(
            "Refusing to export ML-KEM decapsulation key bytes. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown.</exception>
    protected override void ExportPrivateSeedCore(Span<byte> destination)
        => throw new InsecureOperationException(
            "Refusing to export ML-KEM private seed. PKCS#11 keys are non-extractable by design.");

    /// <inheritdoc/>
    /// <exception cref="InsecureOperationException">Always thrown.</exception>
    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        => throw new InsecureOperationException(
            "Refusing to export ML-KEM decapsulation key as PKCS#8. PKCS#11 keys are non-extractable by design.");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void GuardExtraction(bool encapsulating)
    {
        if (_key.AllowInsecure) return;

        string verb = encapsulating ? "Encapsulate" : "Decapsulate";
        throw new InsecureOperationException(
            $"MLKemPkcs11.{verb} extracts the shared-secret bytes from the token. " +
            $"This violates the non-extractable-by-default posture. Use Pkcs11Key.{verb}Key " +
            $"for the on-token-only path, or set Pkcs11Workspace.AllowInsecure = true " +
            $"(or use Pkcs11Workspace.AllowInsecureScope()) to opt in.");
    }

    private static MLKemAlgorithm ResolveAlgorithm(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_ML_KEM)
            throw new ArgumentException(
                $"Expected an ML-KEM key, got {key.KeyType}.", nameof(key));

        var attrs = key.GetAttributeValue(CKA.CKA_PARAMETER_SET);
        try
        {
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
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
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

    private static void ReadAndCopySecret(Pkcs11Key sharedKey, Span<byte> destination)
    {
        var attrs = sharedKey.GetAttributeValue(CKA.CKA_VALUE);
        byte[]? value = null;
        try
        {
            if (attrs[0].CannotBeRead)
                throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                    "MLKemPkcs11 (shared-secret CKA_VALUE unreadable; token rejected the extractable template)");

            value = attrs[0].GetValueAsByteArray();
            // Validate the length as strictly as the ciphertext path (CopyExact): a short CKA_VALUE
            // must not silently leave a partially-filled shared secret.
            if (value.Length != destination.Length)
                throw Pkcs11Exception.Create(CKR.CKR_GENERAL_ERROR,
                    $"Token returned {value.Length}-byte shared secret; expected {destination.Length} bytes.");
            value.CopyTo(destination);
        }
        finally
        {
            if (value is not null) CryptographicOperations.ZeroMemory(value);
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <summary>
    /// Destroys the extracted, extractable shared-secret object on the token (<c>C_DestroyObject</c>).
    /// Unlike a fully best-effort cleanup, a destroy failure is surfaced to the caller: if the
    /// object cannot be destroyed, an extractable copy of the shared secret lingers on-token, which
    /// the callers must not silently ignore. Disposal of the managed <see cref="Pkcs11Key"/> wrapper
    /// is handled by the callers' <c>finally</c>.
    /// </summary>
    private static void DestroyExtractedSecret(Pkcs11Key sharedKey)
    {
        try
        {
            sharedKey.Delete();
        }
        catch (Pkcs11Exception ex)
        {
            throw Pkcs11Exception.Create(ex.ReturnValue,
                "MLKemPkcs11: C_DestroyObject failed for the extracted shared-secret object — an " +
                "extractable copy of the shared secret may remain on-token and must be destroyed manually");
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
