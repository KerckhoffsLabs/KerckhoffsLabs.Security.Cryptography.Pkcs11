using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="System.Security.Cryptography.AesCcm"/>-shaped wrapper over a
/// PKCS#11 AES key. AesCcm is sealed in the BCL so this is a wrapper, not a subclass.
/// Method shapes mirror the BCL.
/// </summary>
public sealed class AesCcmPkcs11 : IDisposable
{
    public static System.Security.Cryptography.KeySizes NonceByteSizes
        => System.Security.Cryptography.AesCcm.NonceByteSizes;

    public static System.Security.Cryptography.KeySizes TagByteSizes
        => System.Security.Cryptography.AesCcm.TagByteSizes;

    private readonly Pkcs11Key _key;
    private bool _disposed;

    public AesCcmPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_AES)
            throw new ArgumentException(
                $"Expected an AES key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <summary>
    /// Does not dispose the underlying <see cref="Pkcs11Key"/> — the caller retains
    /// ownership. Provided for API symmetry with <see cref="System.Security.Cryptography.AesCcm"/>.
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

        using var mech = new Mechanism(CKM.CKM_AES_CCM,
            new CkmAesCcmParams(plaintext.Length, nonce, associatedData, macLen: tag.Length));

        // Session.Encrypt returns ciphertext || tag concatenated.
        byte[] result = _key.Encrypt(mech, plaintext);
        if (result.Length != plaintext.Length + tag.Length)
            throw new InvalidOperationException(
                $"AES-CCM encrypt returned {result.Length} bytes; expected {plaintext.Length + tag.Length}.");

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
        ValidateNonceAndTag(nonce, tag.Length);
        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("plaintext length must equal ciphertext length.", nameof(plaintext));

        using var mech = new Mechanism(CKM.CKM_AES_CCM,
            new CkmAesCcmParams(ciphertext.Length, nonce, associatedData, macLen: tag.Length));

        // PKCS#11 expects ciphertext || tag concatenated.
        byte[] combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));

        byte[] result = _key.Decrypt(mech, combined);
        if (result.Length != plaintext.Length)
            throw new InvalidOperationException(
                $"AES-CCM decrypt returned {result.Length} bytes; expected {plaintext.Length}.");
        result.CopyTo(plaintext);
    }
}
