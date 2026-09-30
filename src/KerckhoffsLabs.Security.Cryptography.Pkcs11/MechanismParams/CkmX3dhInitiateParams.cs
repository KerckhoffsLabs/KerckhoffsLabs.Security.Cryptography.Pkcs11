using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_INITIATE_PARAMS"/>. Used with CKM_X3DH_INITIALIZE — Signal X3DH initiator side (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// Every key must come from the workspace that performs the derive; it is resolved to its object
/// handle when the operation runs, and a disposed key or one from another workspace is refused there.
/// </remarks>
public sealed class CkmX3dhInitiateParams : MechanismParameters
{
    private readonly byte[] _prekeySignatureBytes;
    private readonly byte[] _onetimeKeyBytes;
    private readonly CKM _kdf;
    private readonly Pkcs11Key _peerIdentity;
    private readonly Pkcs11Key _peerPrekey;
    private readonly Pkcs11Key _ownIdentity;
    private readonly Pkcs11Key _ownEphemeral;

    /// <summary>
    /// Initializes X3DH initiator parameters.
    /// </summary>
    /// <param name="kdf">
    /// KDF algorithm tag (CK_X3DH_KDF_TYPE). The spec typedefs this as a bare <c>CK_ULONG</c> with
    /// no constants of its own, reusing the mechanism-type namespace.
    /// </param>
    /// <param name="peerIdentity">Peer's identity key; its public-key object is used.</param>
    /// <param name="peerPrekey">Peer's signed prekey; its public-key object is used.</param>
    /// <param name="prekeySignature">Peer's prekey signature bytes.</param>
    /// <param name="onetimeKey">Optional peer one-time prekey value.</param>
    /// <param name="ownIdentity">Our own identity key; its private-key object is used.</param>
    /// <param name="ownEphemeral">Our own ephemeral key; its private-key object is used.</param>
    /// <exception cref="ArgumentNullException">Thrown if any key is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if a peer key has no public-key object, or an own key has no private-key object.</exception>
    public CkmX3dhInitiateParams(CKM kdf, Pkcs11Key peerIdentity, Pkcs11Key peerPrekey, ReadOnlySpan<byte> prekeySignature, ReadOnlySpan<byte> onetimeKey, Pkcs11Key ownIdentity, Pkcs11Key ownEphemeral)
    {
        ArgumentNullException.ThrowIfNull(peerIdentity);
        ArgumentNullException.ThrowIfNull(peerPrekey);
        ArgumentNullException.ThrowIfNull(ownIdentity);
        ArgumentNullException.ThrowIfNull(ownEphemeral);
        peerIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(peerIdentity));
        peerPrekey.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(peerPrekey));
        ownIdentity.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(ownIdentity));
        ownEphemeral.EnsureHasParameterHandle(KeyHandlePart.Private, nameof(ownEphemeral));

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
        return new CK_X3DH_INITIATE_PARAMS
        {
            Kdf = CkULong.From((ulong)_kdf, "kdf"),
            PeerIdentity = scope.KeyHandle(_peerIdentity, KeyHandlePart.Public, "peerIdentity"),
            PeerPrekey = scope.KeyHandle(_peerPrekey, KeyHandlePart.Public, "peerPrekey"),
            PrekeySignature = scope.Write(_prekeySignatureBytes),
            OnetimeKey = scope.Write(_onetimeKeyBytes),
            OwnIdentity = scope.KeyHandle(_ownIdentity, KeyHandlePart.Private, "ownIdentity"),
            OwnEphemeral = scope.KeyHandle(_ownEphemeral, KeyHandlePart.Private, "ownEphemeral"),
        };
    }
}
