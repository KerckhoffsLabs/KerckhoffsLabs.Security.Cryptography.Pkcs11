using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="System.Security.Cryptography.AesGcm"/>-shaped wrapper over a
/// PKCS#11 AES key. AesGcm is sealed in the BCL so this is a wrapper, not a subclass.
/// Method shapes mirror the BCL.
/// </summary>
public sealed class AesGcmPkcs11 : IDisposable
{
    /// <summary>Authentication-tag sizes (in bytes) supported by AES-GCM; mirrors <see cref="System.Security.Cryptography.AesGcm.TagByteSizes"/>.</summary>
    public static System.Security.Cryptography.KeySizes TagByteSizes
        => System.Security.Cryptography.AesGcm.TagByteSizes;

    /// <summary>Nonce sizes (in bytes) supported by AES-GCM; mirrors <see cref="System.Security.Cryptography.AesGcm.NonceByteSizes"/>.</summary>
    public static System.Security.Cryptography.KeySizes NonceByteSizes
        => System.Security.Cryptography.AesGcm.NonceByteSizes;

    private readonly Pkcs11Key _key;
    private bool _disposed;

    /// <summary>
    /// Wraps a PKCS#11 AES key as an <see cref="System.Security.Cryptography.AesGcm"/>-shaped
    /// AEAD provider. Does not take ownership — disposing this provider does not dispose
    /// <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_AES"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not an AES key.</exception>
    public AesGcmPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_AES)
            throw new ArgumentException(
                $"Expected an AES key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <summary>
    /// Does not dispose the underlying <see cref="Pkcs11Key"/> — the caller retains
    /// ownership. Provided for API symmetry with <see cref="System.Security.Cryptography.AesGcm"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static void ValidateNonceAndTag(ReadOnlySpan<byte> nonce, int tagLength)
    {
        var ns = NonceByteSizes;
        if (nonce.Length < ns.MinSize || nonce.Length > ns.MaxSize
            || (ns.SkipSize > 0 && (nonce.Length - ns.MinSize) % ns.SkipSize != 0))
            throw new ArgumentException(
                $"Nonce length must be between {ns.MinSize} and {ns.MaxSize} bytes (step {ns.SkipSize}); got {nonce.Length}.",
                nameof(nonce));

        var ts = TagByteSizes;
        if (tagLength < ts.MinSize || tagLength > ts.MaxSize
            || (ts.SkipSize > 0 && (tagLength - ts.MinSize) % ts.SkipSize != 0))
            throw new ArgumentException(
                $"Tag length must be between {ts.MinSize} and {ts.MaxSize} bytes (step {ts.SkipSize}); got {tagLength}.",
                nameof(tagLength));
    }

    /// <summary>
    /// Encrypts data and writes the authentication tag using the token-resident AES key —
    /// one-shot AES-GCM AEAD, mirroring <see cref="System.Security.Cryptography.AesGcm"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> or <paramref name="tag"/> has an invalid length, or <paramref name="ciphertext"/> length does not equal <paramref name="plaintext"/> length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Encrypt</c> / <c>C_MessageEncrypt</c> call.</exception>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ValidateNonceAndTag(nonce, tag.Length);
        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("ciphertext length must equal plaintext length.", nameof(ciphertext));

        if (_key.SupportsMessageApi)
        {
            try
            {
                // PKCS#11 v3.0 message-mode path — tag is returned via params, not appended.
                using var msgParams = CkmGcmMessageParams.ForEncrypt(nonce, tag.Length);
                using var mech = new Mechanism(CKM.CKM_AES_GCM);
                byte[] ct = _key.MessageEncrypt(mech, msgParams, associatedData, plaintext);
                if (ct.Length != plaintext.Length)
                    throw new InvalidOperationException(
                        $"AES-GCM message encrypt returned {ct.Length} bytes; expected {plaintext.Length}.");
                ct.CopyTo(ciphertext);
                msgParams.CopyTagTo(tag);
                return;
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_FUNCTION_NOT_SUPPORTED)
            {
                // Some modules export the v3.0 message-API entry points but do not implement AES-GCM
                // through them (e.g. opencryptoki). C_MessageEncryptInit is the first call, so nothing
                // was written yet — fall through to the v2.40 single-part path.
            }
        }

        // v2.40 fallback: ciphertext || tag concatenated.
        using var legacyMech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));
        byte[] result = _key.Encrypt(legacyMech, plaintext);
        if (result.Length != plaintext.Length + tag.Length)
            throw new InvalidOperationException(
                $"AES-GCM encrypt returned {result.Length} bytes; expected {plaintext.Length + tag.Length}.");
        result.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        result.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
    }

    /// <summary>
    /// Verifies the authentication tag and decrypts using the token-resident AES key —
    /// one-shot AES-GCM AEAD, mirroring <see cref="System.Security.Cryptography.AesGcm"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> or <paramref name="tag"/> has an invalid length, or <paramref name="plaintext"/> length does not equal <paramref name="ciphertext"/> length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Decrypt</c> / <c>C_DecryptMessage</c> call; an authentication failure surfaces as <see cref="CKR.CKR_ENCRYPTED_DATA_INVALID"/> or <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/>.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ValidateNonceAndTag(nonce, tag.Length);
        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("plaintext length must equal ciphertext length.", nameof(plaintext));

        if (_key.SupportsMessageApi)
        {
            try
            {
                using var msgParams = CkmGcmMessageParams.ForDecrypt(nonce, tag);
                using var mech = new Mechanism(CKM.CKM_AES_GCM);
                byte[] pt = _key.MessageDecrypt(mech, msgParams, associatedData, ciphertext);
                try
                {
                    if (pt.Length != plaintext.Length)
                        throw new InvalidOperationException(
                            $"AES-GCM message decrypt returned {pt.Length} bytes; expected {plaintext.Length}.");
                    pt.CopyTo(plaintext);
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(pt);
                }
                return;
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_FUNCTION_NOT_SUPPORTED)
            {
                // Module advertises but does not implement AES-GCM via the message API (e.g.
                // opencryptoki). C_MessageDecryptInit is the first call — fall through to v2.40. A
                // genuine tag failure surfaces a different return code and still propagates.
            }
        }

        // v2.40 fallback: PKCS#11 expects ciphertext || tag concatenated.
        using var legacyMech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));
        byte[] combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));
        byte[] result = _key.Decrypt(legacyMech, combined);
        try
        {
            if (result.Length != plaintext.Length)
                throw new InvalidOperationException(
                    $"AES-GCM decrypt returned {result.Length} bytes; expected {plaintext.Length}.");
            result.CopyTo(plaintext);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(result);
        }
    }
}
