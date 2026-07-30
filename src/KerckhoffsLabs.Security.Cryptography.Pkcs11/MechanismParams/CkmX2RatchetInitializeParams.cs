using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_INITIALIZE_PARAMS"/>. Used with CKM_X2RATCHET_INITIALIZE — Signal Double-Ratchet initiator side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX2RatchetInitializeParams : MechanismParameters
{
    private readonly byte[] _skBytes;
    private readonly ulong _peerPublicPrekey;
    private readonly ulong _peerPublicIdentity;
    private readonly ulong _ownPublicIdentity;
    private readonly bool _encryptedHeader;
    private readonly ulong _curve;
    private readonly CKM _aeadMechanism;
    private readonly ulong _kdfMechanism;

    /// <summary>
    /// Initializes X2 Ratchet initiator parameters.
    /// </summary>
    /// <param name="sk">Initial shared-secret bytes (typically 32 from X3DH).</param>
    /// <param name="peerPublicPrekey">Peer's public-prekey handle.</param>
    /// <param name="peerPublicIdentity">Peer's public-identity handle.</param>
    /// <param name="ownPublicIdentity">Our own public-identity handle.</param>
    /// <param name="encryptedHeader">True to enable header encryption.</param>
    /// <param name="curve">Elliptic curve identifier.</param>
    /// <param name="aeadMechanism">AEAD mechanism for messages.</param>
    /// <param name="kdfMechanism">KDF mechanism for the ratchet (CK_X2RATCHET_KDF_TYPE).</param>
    public CkmX2RatchetInitializeParams(ReadOnlySpan<byte> sk, ulong peerPublicPrekey, ulong peerPublicIdentity, ulong ownPublicIdentity, bool encryptedHeader, ulong curve, CKM aeadMechanism, ulong kdfMechanism)
    {
        if (sk.IsEmpty) throw new ArgumentException("Shared-secret bytes must not be empty.", nameof(sk));

        _skBytes = sk.ToArray();
        _peerPublicPrekey = peerPublicPrekey;
        _peerPublicIdentity = peerPublicIdentity;
        _ownPublicIdentity = ownPublicIdentity;
        _encryptedHeader = encryptedHeader;
        _curve = curve;
        _aeadMechanism = aeadMechanism;
        _kdfMechanism = kdfMechanism;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_X2RATCHET_INITIALIZE_PARAMS
        {
            Sk = scope.Write(_skBytes),
            PeerPublicPrekey = (NativeCULong)_peerPublicPrekey,
            PeerPublicIdentity = (NativeCULong)_peerPublicIdentity,
            OwnPublicIdentity = (NativeCULong)_ownPublicIdentity,
            EncryptedHeader = _encryptedHeader,
            Curve = (NativeCULong)_curve,
            AeadMechanism = _aeadMechanism.ToCULong(),
            KdfMechanism = (NativeCULong)_kdfMechanism,
        };
    }
}
