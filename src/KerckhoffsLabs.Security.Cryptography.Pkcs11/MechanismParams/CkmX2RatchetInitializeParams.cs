using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X2RATCHET_INITIALIZE_PARAMS"/>. Used with CKM_X2RATCHET_INITIALIZE — Signal Double-Ratchet initiator side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX2RatchetInitializeParams : IMechanismParams
{
    private CK_X2RATCHET_INITIALIZE_PARAMS _lowLevelParams;
    private IntPtr _sk;
    private bool _disposed;

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
        _sk = UnmanagedMemory.Allocate(sk.Length);
        UnmanagedMemory.Write(_sk, sk);

        _lowLevelParams = new()
        {
            Sk = _sk,
            PeerPublicPrekey = (NativeCULong)peerPublicPrekey,
            PeerPublicIdentity = (NativeCULong)peerPublicIdentity,
            OwnPublicIdentity = (NativeCULong)ownPublicIdentity,
            EncryptedHeader = encryptedHeader,
            Curve = (NativeCULong)curve,
            AeadMechanism = (NativeCULong)(ulong)aeadMechanism,
            KdfMechanism = (NativeCULong)kdfMechanism,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _sk);
        _lowLevelParams.Sk = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmX2RatchetInitializeParams() => Dispose();
}
