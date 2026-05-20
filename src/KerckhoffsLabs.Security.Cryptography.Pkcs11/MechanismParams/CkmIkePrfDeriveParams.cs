using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_IKE_PRF_DERIVE_PARAMS"/>. Used with CKM_IKE_PRF_DERIVE (PKCS#11 v3.0).
/// </summary>
public sealed class CkmIkePrfDeriveParams : MechanismParameters
{
    private CK_IKE_PRF_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _ni;
    private IntPtr _nr;
    private bool _disposed;

    /// <summary>
    /// Initializes IKE PRF derive parameters.
    /// </summary>
    /// <param name="prfMechanism">PRF mechanism.</param>
    /// <param name="dataAsKey">True to treat the input data as the key material.</param>
    /// <param name="rekey">True to perform a rekey-style derivation.</param>
    /// <param name="ni">Initiator nonce (Ni).</param>
    /// <param name="nr">Responder nonce (Nr).</param>
    /// <param name="newKey">New-key handle used in some rekey flows.</param>
    public CkmIkePrfDeriveParams(CKM prfMechanism, bool dataAsKey, bool rekey, ReadOnlySpan<byte> ni, ReadOnlySpan<byte> nr, ulong newKey)
    {
        if (!ni.IsEmpty)
        {
            _ni = UnmanagedMemory.Allocate(ni.Length);
            UnmanagedMemory.Write(_ni, ni);
        }

        if (!nr.IsEmpty)
        {
            _nr = UnmanagedMemory.Allocate(nr.Length);
            UnmanagedMemory.Write(_nr, nr);
        }

        _lowLevelParams = new()
        {
            PrfMechanism = (NativeCULong)(ulong)prfMechanism,
            DataAsKey = dataAsKey,
            Rekey = rekey,
            Ni = _ni,
            NiLen = (NativeCULong)ni.Length,
            Nr = _nr,
            NrLen = (NativeCULong)nr.Length,
            NewKey = (NativeCULong)newKey,
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
        UnmanagedMemory.Free(ref _ni);
        UnmanagedMemory.Free(ref _nr);
        _lowLevelParams.Ni = IntPtr.Zero;
        _lowLevelParams.Nr = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmIkePrfDeriveParams() => Dispose();
}
