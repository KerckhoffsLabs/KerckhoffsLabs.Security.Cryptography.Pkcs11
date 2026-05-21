using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// BCL-aligned <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>-shaped
/// wrapper over a PKCS#11 ChaCha20 key. ChaCha20Poly1305 is sealed in the BCL so
/// this is a wrapper, not a subclass. Method shapes mirror the BCL.
/// </summary>
public sealed class ChaCha20Poly1305Pkcs11 : IDisposable
{
    // ChaCha20-Poly1305 mandates exactly 12-byte nonce and 16-byte tag per RFC 8439.
    // The BCL ChaCha20Poly1305 does not expose these as static KeySizes properties, so
    // we define the constants here to mirror the shape of AesGcm / AesCcm wrappers.
    /// <summary>Nonce size (in bytes): always exactly 12, per RFC 8439.</summary>
    public static System.Security.Cryptography.KeySizes NonceByteSizes
        => new System.Security.Cryptography.KeySizes(12, 12, 1);

    /// <summary>Authentication-tag size (in bytes): always exactly 16, per RFC 8439.</summary>
    public static System.Security.Cryptography.KeySizes TagByteSizes
        => new System.Security.Cryptography.KeySizes(16, 16, 1);

    private readonly Pkcs11Key _key;
    private bool _disposed;

    /// <summary>
    /// Wraps a PKCS#11 ChaCha20 key as a
    /// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>-shaped AEAD provider.
    /// Does not take ownership — disposing this provider does not dispose <paramref name="key"/>.
    /// </summary>
    /// <param name="key">A token-resident PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/>
    /// is <see cref="CKK.CKK_CHACHA20"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not a ChaCha20 key.</exception>
    public ChaCha20Poly1305Pkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_CHACHA20)
            throw new ArgumentException(
                $"Expected a ChaCha20 key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <summary>
    /// Does not dispose the underlying <see cref="Pkcs11Key"/> — the caller retains
    /// ownership. Provided for API symmetry with
    /// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>.
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
    /// Encrypts data and writes the authentication tag using the token-resident ChaCha20 key —
    /// one-shot ChaCha20-Poly1305 AEAD, mirroring <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>.
    /// </summary>
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
            using var msgParams = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(nonce);
            using var mech = new Mechanism(CKM.CKM_CHACHA20_POLY1305);
            byte[] ct = _key.MessageEncrypt(mech, msgParams, associatedData, plaintext);
            if (ct.Length != plaintext.Length)
                throw new InvalidOperationException(
                    $"ChaCha20-Poly1305 message encrypt returned {ct.Length} bytes; expected {plaintext.Length}.");
            ct.CopyTo(ciphertext);
            msgParams.CopyTagTo(tag);
            return;
        }

        // v2.40 fallback: ciphertext || tag concatenated.
        using var legacyMech = new Mechanism(CKM.CKM_CHACHA20_POLY1305,
            new CkmSalsa20ChaCha20Poly1305Params(nonce, associatedData));
        byte[] result = _key.Encrypt(legacyMech, plaintext);
        if (result.Length != plaintext.Length + tag.Length)
            throw new InvalidOperationException(
                $"ChaCha20-Poly1305 encrypt returned {result.Length} bytes; expected {plaintext.Length + tag.Length}.");
        result.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        result.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
    }

    /// <summary>
    /// Verifies the authentication tag and decrypts using the token-resident ChaCha20 key —
    /// one-shot ChaCha20-Poly1305 AEAD, mirroring <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>.
    /// </summary>
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
            using var msgParams = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(nonce, tag);
            using var mech = new Mechanism(CKM.CKM_CHACHA20_POLY1305);
            byte[] pt = _key.MessageDecrypt(mech, msgParams, associatedData, ciphertext);
            if (pt.Length != plaintext.Length)
                throw new InvalidOperationException(
                    $"ChaCha20-Poly1305 message decrypt returned {pt.Length} bytes; expected {plaintext.Length}.");
            pt.CopyTo(plaintext);
            return;
        }

        // v2.40 fallback: PKCS#11 expects ciphertext || tag concatenated.
        using var legacyMech = new Mechanism(CKM.CKM_CHACHA20_POLY1305,
            new CkmSalsa20ChaCha20Poly1305Params(nonce, associatedData));
        byte[] combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));
        byte[] result = _key.Decrypt(legacyMech, combined);
        if (result.Length != plaintext.Length)
            throw new InvalidOperationException(
                $"ChaCha20-Poly1305 decrypt returned {result.Length} bytes; expected {plaintext.Length}.");
        result.CopyTo(plaintext);
    }
}
