using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="System.Security.Cryptography.AesGcm"/>-shaped wrapper over a
/// PKCS#11 AES key. AesGcm is sealed in the BCL so this is a wrapper, not a subclass.
/// Method shapes mirror the BCL.
/// </summary>
public sealed class AesGcmPkcs11 : IDisposable
{
    public static System.Security.Cryptography.KeySizes TagByteSizes
        => System.Security.Cryptography.AesGcm.TagByteSizes;

    public static System.Security.Cryptography.KeySizes NonceByteSizes
        => System.Security.Cryptography.AesGcm.NonceByteSizes;

    private readonly Pkcs11Key _key;
    private bool _disposed;

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
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("ciphertext length must equal plaintext length.", nameof(ciphertext));

        using var mech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));

        // Session.Encrypt returns ciphertext || tag concatenated.
        byte[] result = _key.Encrypt(mech, plaintext);
        if (result.Length != plaintext.Length + tag.Length)
            throw new InvalidOperationException(
                $"AES-GCM encrypt returned {result.Length} bytes; expected {plaintext.Length + tag.Length}.");

        result.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        result.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
    }

    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("plaintext length must equal ciphertext length.", nameof(plaintext));

        using var mech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));

        // PKCS#11 expects ciphertext || tag concatenated.
        byte[] combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));

        byte[] result = _key.Decrypt(mech, combined);
        if (result.Length != plaintext.Length)
            throw new InvalidOperationException(
                $"AES-GCM decrypt returned {result.Length} bytes; expected {plaintext.Length}.");
        result.CopyTo(plaintext);
    }
}
