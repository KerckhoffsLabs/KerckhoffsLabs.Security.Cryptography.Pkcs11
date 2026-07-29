using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_RESPOND_PARAMS"/>. Used with CKM_X2RATCHET_RESPOND — Signal Double-Ratchet responder side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX2RatchetRespondParams : MechanismParameters
{
    private CK_X2RATCHET_RESPOND_PARAMS _lowLevelParams;
    private IntPtr _sk;
    private readonly byte[] _skBytes;
    private bool _disposed;

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
        _sk = UnmanagedMemory.Allocate(sk.Length);
        UnmanagedMemory.Write(_sk, sk);

        _skBytes = sk.ToArray();

        _lowLevelParams = new()
        {
            Sk = _sk,
            OwnPrekey = (NativeCULong)ownPrekey,
            InitiatorIdentity = (NativeCULong)initiatorIdentity,
            OwnPublicIdentity = (NativeCULong)ownPublicIdentity,
            EncryptedHeader = encryptedHeader,
            Curve = (NativeCULong)curve,
            AeadMechanism = (NativeCULong)(ulong)aeadMechanism,
            KdfMechanism = (NativeCULong)kdfMechanism,
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
        return new CK_X2RATCHET_RESPOND_PARAMS
        {
            Sk = scope.Write(_skBytes),
            OwnPrekey = _lowLevelParams.OwnPrekey,
            InitiatorIdentity = _lowLevelParams.InitiatorIdentity,
            OwnPublicIdentity = _lowLevelParams.OwnPublicIdentity,
            EncryptedHeader = _lowLevelParams.EncryptedHeader,
            Curve = _lowLevelParams.Curve,
            AeadMechanism = _lowLevelParams.AeadMechanism,
            KdfMechanism = _lowLevelParams.KdfMechanism,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _sk);
        _lowLevelParams.Sk = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmX2RatchetRespondParams() => Dispose(false);
}
