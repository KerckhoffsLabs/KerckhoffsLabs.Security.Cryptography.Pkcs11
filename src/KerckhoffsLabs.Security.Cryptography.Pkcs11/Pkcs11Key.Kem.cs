using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Key
{
    /// <summary>
    /// Encapsulates a fresh shared secret against this key's public handle and returns its bytes: the
    /// PKCS#11 counterpart of <see cref="MLKem.Encapsulate(Span{byte}, Span{byte})"/>. Reading the secret off the
    /// token is an export of <see cref="KeyMaterialExportKind.KemSharedSecret"/>, so the session's policy must allow it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Prefer <see cref="EncapsulateKey(Mechanism, ObjectTemplate, int)"/> where the secret can stay on the token,
    /// sensitive and non-extractable. Use this where it must leave the token, e.g. to feed a KDF off the token.
    /// </para>
    /// <para>
    /// Only <see cref="CKM.CKM_ML_KEM"/>, without parameters, is accepted. The buffers' lengths are the parameter
    /// set's ciphertext and shared-secret sizes (FIPS 203); the token's answer must match them exactly.
    /// </para>
    /// <para>
    /// The secret is created as an extractable, non-sensitive session generic secret, read and destroyed. On any
    /// failure <paramref name="sharedSecret"/> is zeroed, so a secret is never handed back alongside an exception.
    /// </para>
    /// </remarks>
    /// <param name="mechanism">The KEM: <see cref="CKM.CKM_ML_KEM"/>.</param>
    /// <param name="ciphertext">Receives the ciphertext for the decapsulator; its length is the parameter set's.</param>
    /// <param name="sharedSecret">Receives the shared secret; its length is the parameter set's.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="mechanism"/> is not <see cref="CKM.CKM_ML_KEM"/> without parameters, or either buffer is empty.</exception>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the session's <see cref="Pkcs11Session.Policy"/> permits reading the shared secret off the
    /// token (<see cref="KeyMaterialExportKind.KemSharedSecret"/>).
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Thrown if the token does not expose the secret, returns a secret or ciphertext of the wrong length, or fails
    /// to destroy the secret object after reading it (the module's <see cref="Pkcs11Exception"/> is the inner exception).
    /// </exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no public handle is reachable; otherwise propagated from <c>C_EncapsulateKey</c> or <c>C_GetAttributeValue</c>.</exception>
    public void EncapsulateSecret(Mechanism mechanism, Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        try
        {
            using var use = Use();
            RequireKemSecretArguments(mechanism, ciphertext, sharedSecret);
            int ciphertextLength = ciphertext.Length;

            // Encapsulation uses no private key, so the read-back judges none.
            using SecretReadBack readBack = _session.BeginReadBack(KeyMaterialExportKind.KemSharedSecret);
            using ObjectTemplate template = KemSecretTemplate(sharedSecret.Length, includeValueLen: true);
            byte[] ct = [];
            // The ciphertext length is fixed by the parameter set, so the token gets a pre-sized buffer in one call
            // rather than a NULL-buffer length probe (which SoftHSM does not honour). The read-back owns the secret
            // key from here; the ciphertext is checked with the secret, so a bad one fails the read-back (zeroing
            // the secret and destroying the key) rather than following it.
            byte[] value = readBack.Read(
                grant =>
                {
                    EncapsulationResult encapsulated = EncapsulateKey(mechanism, template, ciphertextLength, grant);
                    ct = encapsulated.Ciphertext;
                    return encapsulated.SharedSecret;
                },
                sharedSecret.Length,
                KemSecretFailures,
                _ => RequireCiphertextLength(ct, ciphertextLength));
            CopyOutAndZero(value, sharedSecret);
            ct.CopyTo(ciphertext);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    /// <summary>
    /// Decapsulates the shared secret from <paramref name="ciphertext"/> with this key's private handle and returns
    /// its bytes: the PKCS#11 counterpart of <see cref="MLKem.Decapsulate(ReadOnlySpan{byte}, Span{byte})"/>. Reading
    /// the secret off the token is an export of <see cref="KeyMaterialExportKind.KemSharedSecret"/>, so the session's
    /// policy must allow it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Prefer <see cref="DecapsulateKey(Mechanism, ReadOnlySpan{byte}, ObjectTemplate)"/> where the secret can stay
    /// on the token. The policy judges this key too
    /// (<see cref="KeyMaterialExportRequest.PrivateKey"/>): over a long-lived key, decapsulating a recorded
    /// ciphertext returns what <see cref="DecapsulateKey(Mechanism, ReadOnlySpan{byte}, ObjectTemplate)"/> kept on the token, so by default only session keys are
    /// covered (<see cref="PrivateKeyScope"/>).
    /// </para>
    /// <para>
    /// Only <see cref="CKM.CKM_ML_KEM"/>, without parameters, is accepted. Tokens disagree on whether the
    /// decapsulated secret's template may carry <c>CKA_VALUE_LEN</c> (opencryptoki requires it, SoftHSM refuses it
    /// as read-only); the first decapsulation against a module finds out and every later one uses the form that
    /// worked. On any failure <paramref name="sharedSecret"/> is zeroed.
    /// </para>
    /// </remarks>
    /// <param name="mechanism">The KEM: <see cref="CKM.CKM_ML_KEM"/>.</param>
    /// <param name="ciphertext">The ciphertext from the encapsulator.</param>
    /// <param name="sharedSecret">Receives the shared secret; its length is the parameter set's.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="mechanism"/> is not <see cref="CKM.CKM_ML_KEM"/> without parameters, or either buffer is empty.</exception>
    /// <exception cref="CryptoPolicyViolationException">
    /// Thrown unless the session's <see cref="Pkcs11Session.Policy"/> permits reading the shared secret off the
    /// token (<see cref="KeyMaterialExportKind.KemSharedSecret"/>) over this key.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Thrown if the token does not expose the secret, returns one of the wrong length, or fails to destroy the
    /// secret object after reading it (the module's <see cref="Pkcs11Exception"/> is the inner exception).
    /// </exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no private handle is reachable; otherwise propagated from <c>C_DecapsulateKey</c> or <c>C_GetAttributeValue</c>.</exception>
    /// <exception cref="Exceptions.Pkcs11LoginEndedException">The private key is a private object and the login it was found or made under has ended.</exception>
    public void DecapsulateSecret(Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        try
        {
            using var use = Use();
            RequireKemSecretArguments(mechanism, ciphertext, sharedSecret);

            using SecretReadBack readBack = _session.BeginReadBack(KeyMaterialExportKind.KemSharedSecret, this);
            Pkcs11Library library = _session.Library;
            int length = sharedSecret.Length;
            // A span cannot be captured; the ciphertext is public, so a copy is harmless.
            byte[] ct = ciphertext.ToArray();
            byte[] value = readBack.Read(
                grant => library.MlKemDecapsulateOmitsValueLen switch
                {
                    bool omit => DecapsulateSecretKey(mechanism, ct, length, includeValueLen: !omit, grant),
                    null => DecapsulateSecretKeyProbing(mechanism, ct, length, library, grant),
                },
                length,
                KemSecretFailures);
            CopyOutAndZero(value, sharedSecret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    // First decapsulation against a module: try the conventional CKA_VALUE_LEN form, fall back to omitting it on
    // SoftHSM's read-only rejection, and record the form that worked on the library so later calls skip the probe
    // (and its failed, side-effect-free first attempt).
    private Pkcs11Key DecapsulateSecretKeyProbing(
        Mechanism mechanism, byte[] ciphertext, int length, Pkcs11Library library, KeyMaterial.IReadBackGrant readBack)
    {
        try
        {
            Pkcs11Key sharedKey = DecapsulateSecretKey(mechanism, ciphertext, length, includeValueLen: true, readBack);
            library.MlKemDecapsulateOmitsValueLen = false;
            return sharedKey;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            Pkcs11Key sharedKey = DecapsulateSecretKey(mechanism, ciphertext, length, includeValueLen: false, readBack);
            library.MlKemDecapsulateOmitsValueLen = true;
            return sharedKey;
        }
    }

    // One decapsulation attempt. The secret's length is fixed by the parameter set, so a token that refuses to be
    // told it (unwrap semantics, where CKA_VALUE_LEN is read-only) can be left to work it out.
    private Pkcs11Key DecapsulateSecretKey(
        Mechanism mechanism, byte[] ciphertext, int length, bool includeValueLen, KeyMaterial.IReadBackGrant readBack)
    {
        using ObjectTemplate template = KemSecretTemplate(length, includeValueLen);
        return DecapsulateKey(mechanism, ciphertext, template, readBack);
    }

    // A session-scoped, extractable, non-sensitive generic secret, so its CKA_VALUE can be read back.
    private static ObjectTemplate KemSecretTemplate(int length, bool includeValueLen)
    {
        SecretKeyTemplateBuilder builder = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .OnToken(false)
            .Sensitive(false)
            .Extractable();
        if (includeValueLen)
            builder = builder.ValueLen(length);
        return builder.Build();
    }

    // EncapsulateSecret's and DecapsulateSecret's allow-list: the read-back is only ever a KEM's shared secret.
    private static void RequireKemSecretArguments(Mechanism mechanism, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        if (mechanism.Type != CKM.CKM_ML_KEM || mechanism.Parameters is not null)
            throw new ArgumentException(
                $"Pkcs11Key.EncapsulateSecret and DecapsulateSecret take CKM_ML_KEM without parameters; got {mechanism.Type}.",
                nameof(mechanism));
        if (ciphertext.IsEmpty)
            throw new ArgumentException("The ciphertext is empty.", nameof(ciphertext));
        if (sharedSecret.IsEmpty)
            throw new ArgumentException("The shared-secret buffer is empty.", nameof(sharedSecret));
    }

    // How a KEM shared-secret read-back fails. These are the library's findings, not codes the module returned, so
    // they are CryptographicExceptions (what code written against MLKem catches); a failed destroy wraps the module's
    // Pkcs11Exception, as it leaves an extractable copy of the secret on the token.
    private static readonly ReadBackFailures KemSecretFailures = new(
        () => new CryptographicException(
            "The KEM shared secret's CKA_VALUE is unreadable; the token rejected the extractable template."),
        (actual, expected) => new CryptographicException(
            $"Token returned {actual}-byte shared secret; expected {expected} bytes."),
        ex => new CryptographicException(
            "C_DestroyObject failed for the extracted KEM shared-secret object — an extractable copy of the " +
            "shared secret may remain on-token and must be destroyed manually.", ex));

    private static void RequireCiphertextLength(byte[] ciphertext, int expectedLength)
    {
        if (ciphertext.Length != expectedLength)
            throw new CryptographicException(
                $"Token returned {ciphertext.Length}-byte buffer; expected {expectedLength} bytes for this parameter set.");
    }

    // Copies the read-back value into the caller's span and zeroes the managed copy.
    private static void CopyOutAndZero(byte[] value, Span<byte> destination)
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
}
