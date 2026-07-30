using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_EDDSA_PARAMS"/>. Used with CKM_EDDSA (PKCS#11 v3.1) — needed for the prehash variants (Ed25519ph / Ed448ph) and contextualized signing.
/// </summary>
public sealed class CkmEddsaParams : MechanismParameters
{
    private readonly byte[] _contextDataBytes;
    private readonly bool _phFlag;
    private bool _disposed;

    /// <summary>
    /// Initializes EdDSA parameters.
    /// </summary>
    /// <param name="phFlag">True selects the prehash variant (Ed25519ph / Ed448ph).</param>
    /// <param name="contextData">Optional context bytes; pass <c>default</c> for the unsalted vanilla signature.</param>
    public CkmEddsaParams(bool phFlag, ReadOnlySpan<byte> contextData = default)
    {
        _contextDataBytes = contextData.ToArray();
        _phFlag = phFlag;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_EDDSA_PARAMS
        {
            PhFlag = _phFlag,
            ContextData = scope.Write(_contextDataBytes),
            ContextDataLen = (NativeCULong)_contextDataBytes.Length,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
