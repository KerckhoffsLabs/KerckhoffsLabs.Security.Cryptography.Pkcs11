using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RC2_CBC_PARAMS"/>. Carries the RC2 effective-key-bits and the
/// 8-byte IV for the <c>CKM_RC2_CBC</c> and <c>CKM_RC2_CBC_PAD</c> mechanisms (RFC 2268 / PKCS#11).
/// The IV is an inline <c>[ByValArray]</c> field, so there is no unmanaged memory to own — the
/// marshaller copies the 8 bytes into the struct.
/// </summary>
public sealed class CkmRc2CbcParams : MechanismParameters
{
    private CK_RC2_CBC_PARAMS _lowLevelParams;
    private bool _disposed;

    /// <summary>
    /// Initializes RC2 CBC parameters.
    /// </summary>
    /// <param name="effectiveBits">Effective number of bits in the RC2 search space (RFC 2268, 1–1024).</param>
    /// <param name="iv">The 8-byte initialization vector.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="iv"/> is not exactly 8 bytes.</exception>
    public CkmRc2CbcParams(ulong effectiveBits, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != 8)
            throw new ArgumentException("RC2 CBC IV must be exactly 8 bytes.", nameof(iv));

        _lowLevelParams = new()
        {
            EffectiveBits = (NativeCULong)effectiveBits,
            Iv = iv.ToArray(),
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
