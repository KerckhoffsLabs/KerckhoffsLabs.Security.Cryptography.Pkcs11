using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_RESPOND_PARAMS"/>. Used with CKM_X3DH_RESPOND — Signal X3DH responder side (PKCS#11 v3.0).
/// </summary>
/// <remarks>
/// <c>initiatorIdentity</c> must come from the workspace that performs the derive; it is resolved to
/// its object handle when the operation runs, and a disposed key or one from another workspace is
/// refused there.
/// </remarks>
public sealed class CkmX3dhRespondParams : MechanismParameters
{
    private readonly byte[] _identityIdBytes;
    private readonly byte[] _prekeyIdBytes;
    private readonly byte[] _onetimeIdBytes;
    private readonly byte[] _initiatorEphemeralBytes;
    private readonly CKM _kdf;
    private readonly Pkcs11Key _initiatorIdentity;

    /// <summary>
    /// Initializes X3DH responder parameters.
    /// </summary>
    /// <param name="kdf">
    /// KDF algorithm tag (CK_X3DH_KDF_TYPE). The spec typedefs this as a bare <c>CK_ULONG</c> with
    /// no constants of its own, reusing the mechanism-type namespace.
    /// </param>
    /// <param name="identityId">Identity-key identifier bytes.</param>
    /// <param name="prekeyId">Prekey identifier bytes.</param>
    /// <param name="onetimeId">One-time prekey identifier bytes.</param>
    /// <param name="initiatorIdentity">Initiator's identity key; its public-key object is used.</param>
    /// <param name="initiatorEphemeral">Initiator's ephemeral public-key bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="initiatorIdentity"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="initiatorIdentity"/> has no public-key object.</exception>
    public CkmX3dhRespondParams(CKM kdf, ReadOnlySpan<byte> identityId, ReadOnlySpan<byte> prekeyId, ReadOnlySpan<byte> onetimeId, Pkcs11Key initiatorIdentity, ReadOnlySpan<byte> initiatorEphemeral)
    {
        ArgumentNullException.ThrowIfNull(initiatorIdentity);
        initiatorIdentity.EnsureHasParameterHandle(KeyHandlePart.Public, nameof(initiatorIdentity));

        _identityIdBytes = identityId.IsEmpty ? [] : identityId.ToArray();
        _prekeyIdBytes = prekeyId.IsEmpty ? [] : prekeyId.ToArray();
        _onetimeIdBytes = onetimeId.IsEmpty ? [] : onetimeId.ToArray();
        _initiatorEphemeralBytes = initiatorEphemeral.IsEmpty ? [] : initiatorEphemeral.ToArray();
        _kdf = kdf;
        _initiatorIdentity = initiatorIdentity;
    }

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_X3DH_RESPOND_PARAMS
        {
            Kdf = CkULong.From((ulong)_kdf, "kdf"),
            IdentityId = scope.Write(_identityIdBytes),
            PrekeyId = scope.Write(_prekeyIdBytes),
            OnetimeId = scope.Write(_onetimeIdBytes),
            InitiatorIdentity = scope.KeyHandle(_initiatorIdentity, KeyHandlePart.Public, "initiatorIdentity"),
            InitiatorEphemeral = scope.Write(_initiatorEphemeralBytes),
        });
    }
}
