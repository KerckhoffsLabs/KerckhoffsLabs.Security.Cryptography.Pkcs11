using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_RESPOND_PARAMS"/>. Used with CKM_X3DH_RESPOND — Signal X3DH responder side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX3dhRespondParams : MechanismParameters
{
    private CK_X3DH_RESPOND_PARAMS _lowLevelParams;
    private IntPtr _identityId;
    private IntPtr _prekeyId;
    private IntPtr _onetimeId;
    private IntPtr _initiatorEphemeral;
    private bool _disposed;

    /// <summary>
    /// Initializes X3DH responder parameters.
    /// </summary>
    /// <param name="kdf">KDF algorithm tag (CK_X3DH_KDF_TYPE).</param>
    /// <param name="identityId">Identity-key identifier bytes.</param>
    /// <param name="prekeyId">Prekey identifier bytes.</param>
    /// <param name="onetimeId">One-time prekey identifier bytes.</param>
    /// <param name="initiatorIdentity">Initiator's identity-key handle.</param>
    /// <param name="initiatorEphemeral">Initiator's ephemeral public-key bytes.</param>
    public CkmX3dhRespondParams(ulong kdf, ReadOnlySpan<byte> identityId, ReadOnlySpan<byte> prekeyId, ReadOnlySpan<byte> onetimeId, ulong initiatorIdentity, ReadOnlySpan<byte> initiatorEphemeral)
    {
        if (!identityId.IsEmpty)
        {
            _identityId = UnmanagedMemory.Allocate(identityId.Length);
            UnmanagedMemory.Write(_identityId, identityId);
        }

        if (!prekeyId.IsEmpty)
        {
            _prekeyId = UnmanagedMemory.Allocate(prekeyId.Length);
            UnmanagedMemory.Write(_prekeyId, prekeyId);
        }

        if (!onetimeId.IsEmpty)
        {
            _onetimeId = UnmanagedMemory.Allocate(onetimeId.Length);
            UnmanagedMemory.Write(_onetimeId, onetimeId);
        }

        if (!initiatorEphemeral.IsEmpty)
        {
            _initiatorEphemeral = UnmanagedMemory.Allocate(initiatorEphemeral.Length);
            UnmanagedMemory.Write(_initiatorEphemeral, initiatorEphemeral);
        }

        _lowLevelParams = new()
        {
            Kdf = (NativeCULong)kdf,
            IdentityId = _identityId,
            PrekeyId = _prekeyId,
            OnetimeId = _onetimeId,
            InitiatorIdentity = (NativeCULong)initiatorIdentity,
            InitiatorEphemeral = _initiatorEphemeral,
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
        UnmanagedMemory.Free(ref _identityId);
        UnmanagedMemory.Free(ref _prekeyId);
        UnmanagedMemory.Free(ref _onetimeId);
        UnmanagedMemory.Free(ref _initiatorEphemeral);
        _lowLevelParams.IdentityId = IntPtr.Zero;
        _lowLevelParams.PrekeyId = IntPtr.Zero;
        _lowLevelParams.OnetimeId = IntPtr.Zero;
        _lowLevelParams.InitiatorEphemeral = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmX3dhRespondParams() => Dispose();
}
