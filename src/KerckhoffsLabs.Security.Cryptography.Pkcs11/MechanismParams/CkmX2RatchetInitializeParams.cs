using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_INITIALIZE_PARAMS"/>. Used with CKM_X2RATCHET_INITIALIZE — Signal Double-Ratchet initiator side (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// Every key must come from the workspace that performs the derive; it is resolved to its object
/// handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmX2RatchetInitializeParams : MechanismParameters
{
    private readonly byte[] _skBytes;
    private readonly Pkcs11Key _peerPublicPrekey;
    private readonly Pkcs11Key _peerPublicIdentity;
    private readonly Pkcs11Key _ownPublicIdentity;
    private readonly bool _encryptedHeader;
    private readonly ulong _curve;
    private readonly CKM _aeadMechanism;
    private readonly CKM _kdfMechanism;

    /// <summary>
    /// Initializes X2 Ratchet initiator parameters.
    /// </summary>
    /// <param name="sk">Initial shared-secret bytes (typically 32 from X3DH).</param>
    /// <param name="peerPublicPrekey">Peer's prekey; its public-key object is used.</param>
    /// <param name="peerPublicIdentity">Peer's identity key; its public-key object is used.</param>
    /// <param name="ownPublicIdentity">Our own identity key; its public-key object is used.</param>
    /// <param name="encryptedHeader">True to enable header encryption.</param>
    /// <param name="curve">Elliptic curve identifier. Left untyped: the spec gives this field no dedicated type at all (plain <c>CK_ULONG</c>), unlike <paramref name="kdfMechanism"/>.</param>
    /// <param name="aeadMechanism">AEAD mechanism for messages.</param>
    /// <param name="kdfMechanism">
    /// KDF mechanism for the ratchet (CK_X2RATCHET_KDF_TYPE). The spec typedefs this as a bare
    /// <c>CK_ULONG</c> with no constants of its own, reusing the mechanism-type namespace — the
    /// same convention as <paramref name="aeadMechanism"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown if any key is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="sk"/> is empty, or a key has no public-key object.</exception>
    public CkmX2RatchetInitializeParams(ReadOnlySpan<byte> sk, Pkcs11Key peerPublicPrekey, Pkcs11Key peerPublicIdentity, Pkcs11Key ownPublicIdentity, bool encryptedHeader, ulong curve, CKM aeadMechanism, CKM kdfMechanism)
    {
        ArgumentNullException.ThrowIfNull(peerPublicPrekey);
        ArgumentNullException.ThrowIfNull(peerPublicIdentity);
        ArgumentNullException.ThrowIfNull(ownPublicIdentity);
        peerPublicPrekey.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(peerPublicPrekey));
        peerPublicIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(peerPublicIdentity));
        ownPublicIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(ownPublicIdentity));
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
            PeerPublicPrekey = scope.KeyHandle(_peerPublicPrekey, KeyHandlePart.Public, "peerPublicPrekey"),
            PeerPublicIdentity = scope.KeyHandle(_peerPublicIdentity, KeyHandlePart.Public, "peerPublicIdentity"),
            OwnPublicIdentity = scope.KeyHandle(_ownPublicIdentity, KeyHandlePart.Public, "ownPublicIdentity"),
            EncryptedHeader = _encryptedHeader,
            Curve = CkULong.From(_curve, "curve"),
            AeadMechanism = _aeadMechanism.ToCULong("aeadMechanism"),
            KdfMechanism = _kdfMechanism.ToCULong("kdfMechanism"),
        };
    }
}
