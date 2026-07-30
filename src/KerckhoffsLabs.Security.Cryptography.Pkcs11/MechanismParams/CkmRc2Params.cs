using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RC2_PARAMS"/>. Carries the RC2 effective-key-bits parameter
/// for the <c>CKM_RC2_ECB</c> and <c>CKM_RC2_MAC</c> mechanisms (RFC 2268 / PKCS#11). The struct holds
/// no pointers, so there is no unmanaged memory to own.
/// </summary>
public sealed class CkmRc2Params : MechanismParameters
{
    private readonly ulong _effectiveBits;
    private bool _disposed;

    /// <summary>
    /// Initializes RC2 ECB/MAC parameters.
    /// </summary>
    /// <param name="effectiveBits">Effective number of bits in the RC2 search space (RFC 2268, 1–1024).</param>
    public CkmRc2Params(ulong effectiveBits) => _effectiveBits = effectiveBits;

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_RC2_PARAMS { EffectiveBits = (NativeCULong)_effectiveBits };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
