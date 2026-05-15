using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_EDDSA_PARAMS"/>. Used with CKM_EDDSA (PKCS#11 v3.1) — needed for the prehash variants (Ed25519ph / Ed448ph) and contextualized signing.
/// </summary>
public sealed class CkmEddsaParams : IMechanismParams
{
    private CK_EDDSA_PARAMS _lowLevelParams;
    private IntPtr _contextData;
    private bool _disposed;

    /// <summary>
    /// Initializes EdDSA parameters.
    /// </summary>
    /// <param name="phFlag">True selects the prehash variant (Ed25519ph / Ed448ph).</param>
    /// <param name="contextData">Optional context bytes; pass <c>default</c> for the unsalted vanilla signature.</param>
    public CkmEddsaParams(bool phFlag, ReadOnlySpan<byte> contextData = default)
    {
        if (!contextData.IsEmpty)
        {
            _contextData = UnmanagedMemory.Allocate(contextData.Length);
            UnmanagedMemory.Write(_contextData, contextData);
        }

        _lowLevelParams = new CK_EDDSA_PARAMS
        {
            PhFlag = phFlag,
            ContextDataLen = (NativeCULong)contextData.Length,
            ContextData = _contextData,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _contextData);
        _lowLevelParams.ContextData = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmEddsaParams() => Dispose();
}
