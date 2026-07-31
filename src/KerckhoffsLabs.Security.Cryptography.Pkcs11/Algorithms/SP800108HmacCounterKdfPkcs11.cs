using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="SP800108HmacCounterKdf"/>-shaped wrapper that
/// runs NIST SP800-108 HMAC counter-mode key derivation on a PKCS#11 token
/// (<c>CKM_SP800_108_COUNTER_KDF</c>, PKCS#11 v3.0). <c>SP800108HmacCounterKdf</c> is sealed in the
/// BCL, so this is a wrapper, not a subclass; method shapes mirror the BCL.
/// </summary>
/// <remarks>
/// <para>
/// The long-term KDF key (the SP800-108 <c>KI</c>) is a token-resident <see cref="Pkcs11Key"/> and
/// never enters managed memory — only the <i>derived</i> output is returned. The byte-returning
/// <see cref="DeriveKey(byte[], byte[], int)"/> overloads mirror the BCL and therefore derive an
/// <b>extractable</b> session key so its value can be read back; the base key stays non-extractable.
/// For sub-keys that should remain on the token, use the
/// <see cref="DeriveKey(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ObjectTemplate)"/> overload, which
/// returns a <see cref="Pkcs11Key"/> shaped by the caller's template.
/// </para>
/// <para>
/// Supported PRFs are HMAC-SHA256 / SHA384 / SHA512. HMAC-SHA1 is rejected: it is on the library's
/// deprecated-MAC list, and because the guarded mechanism here is the outer KDF, a SHA-1 PRF would
/// otherwise bypass the secure-defaults gate. The derived fixed-input layout matches the BCL
/// (<c>counter ‖ Label ‖ 0x00 ‖ Context ‖ [L]</c>, 32-bit big-endian counter and length).
/// </para>
/// <para>
/// Does not take ownership of the base key — disposing this provider does not dispose it.
/// </para>
/// <para>
/// <b>Requires <c>Pkcs11Workspace.AllowInsecure</c>.</b> Every method here returns <c>byte[]</c>, so
/// the derived value must be read off the token — this adapter cannot be implemented without
/// extracting key material. The refusal comes from the library's single secure-defaults gate, which
/// declines to create the extractable, non-sensitive key the read-back needs. Use
/// <c>AllowInsecureScope()</c> to opt in for one operation, or stay on the on-token
/// <c>Pkcs11Key.Derive</c> path if the derived key never needs to leave the HSM.
/// </para>
/// </remarks>
public sealed class SP800108HmacCounterKdfPkcs11 : IDisposable
{
    private readonly Pkcs11Key _key;
    private readonly CKM _prf;
    private bool _disposed;

    /// <summary>
    /// Wraps a token-resident generic-secret key as an SP800-108 HMAC counter-mode KDF.
    /// </summary>
    /// <param name="key">The KDF base key (<c>KI</c>); must be <see cref="CKK.CKK_GENERIC_SECRET"/>
    /// with <c>CKA_DERIVE</c> set. Borrowed, not owned.</param>
    /// <param name="hashAlgorithm">PRF hash — SHA256, SHA384, or SHA512.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not a generic-secret key.</exception>
    /// <exception cref="NotSupportedException">Thrown for an unsupported PRF hash.</exception>
    public SP800108HmacCounterKdfPkcs11(Pkcs11Key key, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_GENERIC_SECRET)
            throw new ArgumentException(
                $"Expected a generic-secret HMAC base key (CKK_GENERIC_SECRET), got {key.KeyType}.", nameof(key));
        _prf = PrfForHash(hashAlgorithm);
        _key = key;
    }

    private static CKM PrfForHash(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => CKM.CKM_SHA256_HMAC,
        "SHA384" => CKM.CKM_SHA384_HMAC,
        "SHA512" => CKM.CKM_SHA512_HMAC,
        "SHA1" => throw new NotSupportedException(
            "HMAC-SHA1 is deprecated and not offered as an SP800-108 PRF; use SHA256, SHA384, or SHA512."),
        _ => throw new NotSupportedException(
            $"SP800-108 HMAC counter KDF does not support hash {hash.Name}; use SHA256, SHA384, or SHA512."),
    };

    /// <summary>
    /// Derives <paramref name="derivedKeyLengthInBytes"/> bytes of keying material. Mirrors
    /// <see cref="SP800108HmacCounterKdf.DeriveKey(byte[], byte[], int)"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> or <paramref name="context"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the KDF has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="derivedKeyLengthInBytes"/> is negative.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call, or thrown when the derived bytes cannot be read back.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <see cref="Pkcs11Workspace.AllowInsecure"/> is <c>false</c>: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public byte[] DeriveKey(byte[] label, byte[] context, int derivedKeyLengthInBytes)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(context);
        return DeriveKey((ReadOnlySpan<byte>)label, context, derivedKeyLengthInBytes);
    }

    /// <summary>
    /// Derives <paramref name="derivedKeyLengthInBytes"/> bytes of keying material. Mirrors the
    /// span overload of <see cref="SP800108HmacCounterKdf"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the KDF has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="derivedKeyLengthInBytes"/> is negative.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call, or thrown when the derived bytes cannot be read back.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <see cref="Pkcs11Workspace.AllowInsecure"/> is <c>false</c>: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public byte[] DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int derivedKeyLengthInBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(derivedKeyLengthInBytes);
        // Zero length is a no-op (matches the BCL), and avoids deriving a 0-byte token key.
        if (derivedKeyLengthInBytes == 0)
            return [];
        return DeriveExtractable(label, context, derivedKeyLengthInBytes);
    }

    /// <summary>
    /// Derives keying material into <paramref name="destination"/>. Mirrors the destination-span
    /// overload of <see cref="SP800108HmacCounterKdf"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the KDF has been disposed.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call, or thrown when the derived bytes cannot be read back.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <see cref="Pkcs11Workspace.AllowInsecure"/> is <c>false</c>: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public void DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        // Zero-length destination is a no-op, matching the BCL.
        if (destination.IsEmpty)
            return;

        byte[] derived = DeriveExtractable(label, context, destination.Length);
        try
        {
            derived.CopyTo(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    /// <summary>
    /// Derives a sub-key that stays on the token (or wherever <paramref name="template"/> places it),
    /// returning its <see cref="Pkcs11Key"/> handle rather than raw bytes. Use this to keep derived
    /// key material non-extractable.
    /// </summary>
    /// <param name="label">SP800-108 label bytes.</param>
    /// <param name="context">SP800-108 context bytes.</param>
    /// <param name="template">Template describing the derived key (class, type, length, attributes).</param>
    /// <exception cref="ObjectDisposedException">Thrown if the KDF has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="Exceptions.InsecureOperationException">Thrown if <paramref name="template"/> explicitly requests an extractable or non-sensitive key while the workspace's <c>AllowInsecure</c> gate is off.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(template);

        var p = CkmSp800108KdfParams.CounterModeHmac(_prf, label, context);
        var mech = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, p);
        return _key.Derive(mech, template);
    }

    private byte[] DeriveExtractable(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        var p = CkmSp800108KdfParams.CounterModeHmac(_prf, label, context);
        var mech = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, p);
        // Session-scoped, extractable, non-sensitive generic secret so CKA_VALUE can be read back.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(length)
            .Extractable()
            .Sensitive(false)
            .Build();

        // Public, gated path — the same one an external caller would use. The template asks for an
        // extractable, non-sensitive key, so Pkcs11Session.BuildSecureKeyDefaults refuses unless the
        // workspace has opted in. That single check is the whole policy; there is no adapter-local
        // guard to keep in step with it.
        Pkcs11Key derived = _key.Derive(mech, template);
        bool operationFailed = true;
        try
        {
            var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            try
            {
                if (attrs.Count == 0 || attrs[0].CannotBeRead)
                    throw new InvalidOperationException(
                        "Derived key did not expose CKA_VALUE; the token may not permit reading derived key material.");
                byte[] derivedKey = attrs[0].GetValueAsByteArray();
                operationFailed = false;
                return derivedKey;
            }
            finally
            {
                // ObjectAttribute owns an unmanaged buffer holding the derived key material, and
                // freeing it is what zeroizes it. Without this the secret stays in unmanaged memory
                // for the life of the process.
                foreach (var a in attrs) a.Dispose();
            }
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    /// <summary>
    /// Destroys an ephemeral derived key without letting a cleanup failure hide a real one.
    /// </summary>
    /// <remarks>
    /// A throw from <c>finally</c> <i>replaces</i> an exception already in flight, so a failed
    /// <c>C_DestroyObject</c> would reach the caller in place of whatever actually went wrong. This
    /// suppresses the destroy failure only on that path: when the operation succeeded, the destroy
    /// failure is the only news and is allowed to surface. The key is a session object either way, so
    /// the token collects it at <c>C_CloseSession</c> even when the eager destroy fails.
    /// </remarks>
    private static void DestroyEphemeral(Pkcs11Key derived, bool operationFailed)
    {
        try
        {
            derived.Destroy();
        }
        catch (Pkcs11Exception) when (operationFailed)
        {
            // Deliberately swallowed: see the remarks. The primary exception is the useful one.
        }
        finally
        {
            derived.Dispose();
        }
    }

    /// <summary>
    /// Does not dispose the underlying <see cref="Pkcs11Key"/> — the caller retains ownership.
    /// Provided for API symmetry with <see cref="SP800108HmacCounterKdf"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
