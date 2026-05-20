using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SIGN_ADDITIONAL_CONTEXT"/>. Used with CKM_ML_DSA
/// and CKM_SLH_DSA — the pure (non-prehash) PQC signing mechanisms in PKCS#11 v3.2.
/// </summary>
public sealed class CkmPqcSignParams : MechanismParameters
{
    private CK_SIGN_ADDITIONAL_CONTEXT _lowLevelParams;
    private IntPtr _context;
    private bool _disposed;

    /// <summary>Initializes pure-PQC signing parameters.</summary>
    /// <param name="hedgeVariant">Hedge mode (default <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/>).</param>
    /// <param name="context">Optional context string (max 255 bytes per FIPS 204 §5.2.1 / FIPS 205 §10.2.1). Empty for default.</param>
    /// <exception cref="ArgumentException">If <paramref name="context"/> exceeds 255 bytes.</exception>
    public CkmPqcSignParams(CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED, ReadOnlySpan<byte> context = default)
    {
        if (context.Length > 255)
            throw new ArgumentException("PQC signing context must be at most 255 bytes.", nameof(context));

        if (!context.IsEmpty)
        {
            _context = UnmanagedMemory.Allocate(context.Length);
            UnmanagedMemory.Write(_context, context);
        }

        _lowLevelParams = new()
        {
            HedgeVariant = (NativeCULong)(uint)hedgeVariant,
            Context = _context,
            ContextLen = (NativeCULong)context.Length,
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
        UnmanagedMemory.Free(ref _context);
        _lowLevelParams.Context = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~CkmPqcSignParams() => Dispose();
}
