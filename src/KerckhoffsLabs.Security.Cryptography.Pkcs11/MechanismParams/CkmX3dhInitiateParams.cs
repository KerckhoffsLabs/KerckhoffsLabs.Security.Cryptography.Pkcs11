using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_INITIATE_PARAMS"/>. Used with CKM_X3DH_INITIALIZE — Signal X3DH initiator side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX3dhInitiateParams : MechanismParameters
{
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
        _prekeySignatureBytes = prekeySignature.IsEmpty ? [] : prekeySignature.ToArray();
        _onetimeKeyBytes = onetimeKey.IsEmpty ? [] : onetimeKey.ToArray();
        _kdf = kdf;
        _peerIdentity = peerIdentity;
        _peerPrekey = peerPrekey;
        _ownIdentity = ownIdentity;
        _ownEphemeral = ownEphemeral;
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
        _disposed = true;
    }
}
