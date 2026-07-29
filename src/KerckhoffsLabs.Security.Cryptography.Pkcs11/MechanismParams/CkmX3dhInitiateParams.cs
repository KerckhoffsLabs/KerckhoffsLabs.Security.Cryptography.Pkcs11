using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_INITIATE_PARAMS"/>. Used with CKM_X3DH_INITIALIZE — Signal X3DH initiator side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX3dhInitiateParams : MechanismParameters
{
    private CK_X3DH_INITIATE_PARAMS _lowLevelParams;
    private IntPtr _prekeySignature;
    private IntPtr _onetimeKey;
    private readonly byte[] _prekeySignatureBytes;
    private readonly byte[] _onetimeKeyBytes;
    private readonly ulong _kdf;
    private readonly ulong _peerIdentity;
    private readonly ulong _peerPrekey;
    private readonly ulong _ownIdentity;
    private readonly ulong _ownEphemeral;
    private bool _disposed;

    /// <summary>
    /// Initializes X3DH initiator parameters.
    /// </summary>
    /// <param name="kdf">KDF algorithm tag (CK_X3DH_KDF_TYPE).</param>
    /// <param name="peerIdentity">Peer's identity-key handle.</param>
    /// <param name="peerPrekey">Peer's signed-prekey handle.</param>
    /// <param name="prekeySignature">Peer's prekey signature bytes.</param>
    /// <param name="onetimeKey">Optional peer one-time prekey value.</param>
    /// <param name="ownIdentity">Our own identity-key handle.</param>
    /// <param name="ownEphemeral">Our own ephemeral-key handle.</param>
    public CkmX3dhInitiateParams(ulong kdf, ulong peerIdentity, ulong peerPrekey, ReadOnlySpan<byte> prekeySignature, ReadOnlySpan<byte> onetimeKey, ulong ownIdentity, ulong ownEphemeral)
    {
        if (!prekeySignature.IsEmpty)
        {
            _prekeySignature = UnmanagedMemory.Allocate(prekeySignature.Length);
            UnmanagedMemory.Write(_prekeySignature, prekeySignature);
        }

        if (!onetimeKey.IsEmpty)
        {
            _onetimeKey = UnmanagedMemory.Allocate(onetimeKey.Length);
            UnmanagedMemory.Write(_onetimeKey, onetimeKey);
        }

        _prekeySignatureBytes = prekeySignature.IsEmpty ? [] : prekeySignature.ToArray();
        _onetimeKeyBytes = onetimeKey.IsEmpty ? [] : onetimeKey.ToArray();
        _kdf = kdf;
        _peerIdentity = peerIdentity;
        _peerPrekey = peerPrekey;
        _ownIdentity = ownIdentity;
        _ownEphemeral = ownEphemeral;

        _lowLevelParams = new()
        {
            Kdf = (NativeCULong)kdf,
            PeerIdentity = (NativeCULong)peerIdentity,
            PeerPrekey = (NativeCULong)peerPrekey,
            PrekeySignature = _prekeySignature,
            OnetimeKey = _onetimeKey,
            OwnIdentity = (NativeCULong)ownIdentity,
            OwnEphemeral = (NativeCULong)ownEphemeral,
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_X3DH_INITIATE_PARAMS
        {
            Kdf = (NativeCULong)_kdf,
            PeerIdentity = (NativeCULong)_peerIdentity,
            PeerPrekey = (NativeCULong)_peerPrekey,
            PrekeySignature = scope.Write(_prekeySignatureBytes),
            OnetimeKey = scope.Write(_onetimeKeyBytes),
            OwnIdentity = (NativeCULong)_ownIdentity,
            OwnEphemeral = (NativeCULong)_ownEphemeral,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _prekeySignature);
        UnmanagedMemory.Free(ref _onetimeKey);
        _lowLevelParams.PrekeySignature = IntPtr.Zero;
        _lowLevelParams.OnetimeKey = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmX3dhInitiateParams() => Dispose(false);
}
