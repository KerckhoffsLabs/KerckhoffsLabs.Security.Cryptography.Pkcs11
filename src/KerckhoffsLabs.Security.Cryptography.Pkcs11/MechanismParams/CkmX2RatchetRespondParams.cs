using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_RESPOND_PARAMS"/>. Used with CKM_X2RATCHET_RESPOND — Signal Double-Ratchet responder side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX2RatchetRespondParams : MechanismParameters
{
    private readonly byte[] _skBytes;
    private readonly ulong _ownPrekey;
    private readonly ulong _initiatorIdentity;
    private readonly ulong _ownPublicIdentity;
    private readonly bool _encryptedHeader;
    private readonly ulong _curve;
    private readonly CKM _aeadMechanism;
    private readonly ulong _kdfMechanism;

    /// <summary>
    /// Initializes X2 Ratchet responder parameters.
    /// </summary>
    /// <param name="sk">Initial shared-secret bytes (typically 32 from X3DH).</param>
    /// <param name="ownPrekey">Our own prekey handle.</param>
    /// <param name="initiatorIdentity">Initiator's identity-key handle.</param>
    /// <param name="ownPublicIdentity">Our own public-identity handle.</param>
    /// <param name="encryptedHeader">True to enable header encryption.</param>
    /// <param name="curve">Elliptic curve identifier.</param>
    /// <param name="aeadMechanism">AEAD mechanism for messages.</param>
    /// <param name="kdfMechanism">KDF mechanism for the ratchet (CK_X2RATCHET_KDF_TYPE).</param>
    public CkmX2RatchetRespondParams(ReadOnlySpan<byte> sk, ulong ownPrekey, ulong initiatorIdentity, ulong ownPublicIdentity, bool encryptedHeader, ulong curve, CKM aeadMechanism, ulong kdfMechanism)
    {
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
            OwnPrekey = (NativeCULong)_ownPrekey,
            InitiatorIdentity = (NativeCULong)_initiatorIdentity,
            OwnPublicIdentity = (NativeCULong)_ownPublicIdentity,
            EncryptedHeader = _encryptedHeader,
            Curve = (NativeCULong)_curve,
            AeadMechanism = _aeadMechanism.ToCULong(),
            KdfMechanism = (NativeCULong)_kdfMechanism,
        };
    }
}
