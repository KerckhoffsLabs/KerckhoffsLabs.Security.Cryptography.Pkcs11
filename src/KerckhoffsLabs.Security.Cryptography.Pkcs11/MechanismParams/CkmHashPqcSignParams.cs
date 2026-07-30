using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_HASH_SIGN_ADDITIONAL_CONTEXT"/>. Used with
/// CKM_HASH_ML_DSA and CKM_HASH_SLH_DSA — the prehash PQC signing mechanisms in
/// PKCS#11 v3.2. The data is digested with the chosen hash mechanism before signing.
/// </summary>
public sealed class CkmHashPqcSignParams : MechanismParameters
{
    private readonly byte[] _contextBytes;
    private readonly CKM _hash;
    private readonly CkhHedge _hedgeVariant;

    /// <summary>Initializes prehash-PQC signing parameters.</summary>
    /// <param name="hash">Hash mechanism applied to the data before signing (CKM_SHA256, CKM_SHA3_256, CKM_SHAKE_*, etc.).</param>
    /// <param name="hedgeVariant">Hedge mode.</param>
    /// <param name="context">Optional context string (max 255 bytes).</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="context"/> exceeds 255 bytes.</exception>
    public CkmHashPqcSignParams(
        CKM hash,
        CkhHedge hedgeVariant = CkhHedge.CKH_HEDGE_PREFERRED,
        ReadOnlySpan<byte> context = default)
    {
        if (context.Length > 255)
            throw new ArgumentException("PQC signing context must be at most 255 bytes.", nameof(context));

        _contextBytes = context.ToArray();
        _hash = hash;
        _hedgeVariant = hedgeVariant;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_HASH_SIGN_ADDITIONAL_CONTEXT
        {
            HedgeVariant = (NativeCULong)(uint)_hedgeVariant,
            Context = scope.Write(_contextBytes),
            ContextLen = (NativeCULong)_contextBytes.Length,
            Hash = (NativeCULong)(ulong)_hash,
        };
    }
}
