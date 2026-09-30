using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_RESPOND_PARAMS"/>. Used with CKM_X2RATCHET_RESPOND — Signal Double-Ratchet responder side (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// Every key must come from the workspace that performs the derive; it is resolved to its object
/// handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmX2RatchetRespondParams : MechanismParameters
{
    private readonly byte[] _skBytes;
    private readonly Pkcs11Key _ownPrekey;
    private readonly Pkcs11Key _initiatorIdentity;
    private readonly Pkcs11Key _ownPublicIdentity;
    private readonly bool _encryptedHeader;
    private readonly ulong _curve;
    private readonly CKM _aeadMechanism;
    private readonly CKM _kdfMechanism;

    /// <summary>
    /// Initializes X2 Ratchet responder parameters.
    /// </summary>
    /// <param name="sk">Initial shared-secret bytes (typically 32 from X3DH).</param>
    /// <param name="ownPrekey">Our own prekey; its private-key object is used.</param>
    /// <param name="initiatorIdentity">Initiator's identity key; its public-key object is used.</param>
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
    /// <exception cref="ArgumentException">Thrown if <paramref name="sk"/> is empty, or <paramref name="ownPrekey"/> has no private-key object, or an identity key has no public-key object.</exception>
    public CkmX2RatchetRespondParams(ReadOnlySpan<byte> sk, Pkcs11Key ownPrekey, Pkcs11Key initiatorIdentity, Pkcs11Key ownPublicIdentity, bool encryptedHeader, ulong curve, CKM aeadMechanism, CKM kdfMechanism)
    {
        ArgumentNullException.ThrowIfNull(ownPrekey);
        ArgumentNullException.ThrowIfNull(initiatorIdentity);
        ArgumentNullException.ThrowIfNull(ownPublicIdentity);
        ownPrekey.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(ownPrekey));
        initiatorIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(initiatorIdentity));
        ownPublicIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(ownPublicIdentity));
        if (sk.IsEmpty) throw new ArgumentException("Shared-secret bytes must not be empty.", nameof(sk));

        _skBytes = sk.ToArray();
        _ownPrekey = ownPrekey;
        _initiatorIdentity = initiatorIdentity;
        _ownPublicIdentity = ownPublicIdentity;
        _encryptedHeader = encryptedHeader;
        _curve = curve;
        _aeadMechanism = aeadMechanism;
        _kdfMechanism = kdfMechanism;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_X2RATCHET_RESPOND_PARAMS
        {
            Sk = scope.Write(_skBytes),
            OwnPrekey = scope.KeyHandle(_ownPrekey, KeyHandlePart.Private, "ownPrekey"),
            InitiatorIdentity = scope.KeyHandle(_initiatorIdentity, KeyHandlePart.Public, "initiatorIdentity"),
            OwnPublicIdentity = scope.KeyHandle(_ownPublicIdentity, KeyHandlePart.Public, "ownPublicIdentity"),
            EncryptedHeader = _encryptedHeader,
            Curve = CkULong.From(_curve, "curve"),
            AeadMechanism = _aeadMechanism.ToCULong("aeadMechanism"),
            KdfMechanism = _kdfMechanism.ToCULong("kdfMechanism"),
        };
    }
}
