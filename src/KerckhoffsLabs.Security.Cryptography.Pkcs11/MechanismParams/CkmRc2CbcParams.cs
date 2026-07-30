using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RC2_CBC_PARAMS"/>. Carries the RC2 effective-key-bits and the
/// 8-byte IV for the <c>CKM_RC2_CBC</c> and <c>CKM_RC2_CBC_PAD</c> mechanisms (RFC 2268 / PKCS#11).
/// The IV is an inline fixed-size buffer stored in the struct itself, so there is no unmanaged
/// memory and no separate heap array to own.
/// </summary>
public sealed class CkmRc2CbcParams : MechanismParameters
{
    private readonly ulong _effectiveBits;
    private readonly byte[] _iv;
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

        _effectiveBits = effectiveBits;
        _iv = iv.ToArray();
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // The IV is an inline buffer, which an object initializer cannot assign from a span,
        // so construct first and copy into the field afterwards.
        var lowLevel = new CK_RC2_CBC_PARAMS { EffectiveBits = (NativeCULong)_effectiveBits };
        _iv.CopyTo(lowLevel.Iv);
        return lowLevel;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
