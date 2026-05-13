using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="HMAC"/> provider backed by a PKCS#11 secret key (typically
/// <see cref="CKK.CKK_GENERIC_SECRET"/>). Does NOT take ownership of the underlying key.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 exposes HMAC as a one-shot <c>C_Sign</c> operation; there is no streaming
/// multi-part HMAC API in the spec. This class bridges the BCL's streaming
/// <c>HashCore</c>/<c>HashFinal</c> contract by buffering all data written
/// via <c>HashCore</c> into a <see cref="System.IO.MemoryStream"/> and issuing
/// a single <see cref="Pkcs11Key.Sign(Mechanism, ReadOnlySpan{byte})"/> on
/// <c>HashFinal</c>.
/// </para>
/// <para>
/// Memory usage grows linearly with accumulated input. This is acceptable for the typical
/// HMAC use cases (token signing, cookie sealing, small message authentication codes).
/// For multi-gigabyte inputs, prefer a software HMAC implementation.
/// </para>
/// <para>
/// The key is borrowed — this class does NOT dispose the supplied <see cref="Pkcs11Key"/>.
/// </para>
/// </remarks>
public sealed class HMACPkcs11 : HMAC
{
    private readonly Pkcs11Key _key;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed HMAC instance.
    /// </summary>
    /// <param name="key">
    /// The secret key to use for the HMAC operation. Must carry a sign-capable handle.
    /// This instance does NOT take ownership.
    /// </param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm (SHA1, SHA256, SHA384, or SHA512). The corresponding
    /// <c>CKM_*_HMAC</c> mechanism will be selected automatically.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="hashAlgorithm"/> is not one of the four supported algorithms.
    /// </exception>
    public HMACPkcs11(Pkcs11Key key, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        _hashAlgorithm = hashAlgorithm;
        HashName = hashAlgorithm.Name;
        HashSizeValue = HashSizeFromName(hashAlgorithm) * 8;
    }

    /// <summary>
    /// Resets the internal buffer so the instance can be reused for a new computation.
    /// Called automatically by <see cref="HashAlgorithm.ComputeHash(byte[])"/> before
    /// each new computation.
    /// </summary>
    public override void Initialize() => _buffer.SetLength(0);

    /// <inheritdoc/>
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
        => _buffer.Write(array, ibStart, cbSize);

    /// <inheritdoc/>
    protected override void HashCore(ReadOnlySpan<byte> source)
        => _buffer.Write(source);

    /// <inheritdoc/>
    protected override byte[] HashFinal()
    {
        using var mech = Pkcs11MechanismMap.Hmac(_hashAlgorithm);
        byte[] data = _buffer.ToArray();
        _buffer.SetLength(0);
        return _key.Sign(mech, data);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing) _buffer.Dispose();
        base.Dispose(disposing);
    }

    private static int HashSizeFromName(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => 20,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new NotSupportedException($"Unsupported hash: {hash.Name}."),
    };
}
