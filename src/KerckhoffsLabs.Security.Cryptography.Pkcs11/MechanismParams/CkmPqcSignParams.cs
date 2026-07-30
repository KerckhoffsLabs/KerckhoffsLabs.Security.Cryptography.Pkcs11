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
    private readonly byte[] _contextBytes;
    private readonly CkhHedge _hedgeVariant;

    /// <summary>Initializes pure-PQC signing parameters.</summary>
    /// <param name="hedgeVariant">Hedge mode (default <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/>).</param>
    /// <param name="context">Optional context string (max 255 bytes per FIPS 204 §5.2.1 / FIPS 205 §10.2.1). Empty for default.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="context"/> exceeds 255 bytes.</exception>
    public CkmPqcSignParams(CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED, ReadOnlySpan<byte> context = default)
    {
        if (context.Length > 255)
            throw new ArgumentException("PQC signing context must be at most 255 bytes.", nameof(context));

        _contextBytes = context.ToArray();
        _hedgeVariant = hedgeVariant;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_SIGN_ADDITIONAL_CONTEXT
        {
            HedgeVariant = (NativeCULong)(uint)_hedgeVariant,
            Context = scope.Write(_contextBytes),
            ContextLen = (NativeCULong)_contextBytes.Length,
        };
    }
}
