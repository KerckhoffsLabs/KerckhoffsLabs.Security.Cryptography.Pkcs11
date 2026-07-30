using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_X3DH_RESPOND_PARAMS"/>. Used with CKM_X3DH_RESPOND — Signal X3DH responder side (PKCS#11 v3.0).
/// </summary>
public sealed class CkmX3dhRespondParams : MechanismParameters
{
    private readonly byte[] _identityIdBytes;
    private readonly byte[] _prekeyIdBytes;
    private readonly byte[] _onetimeIdBytes;
    private readonly byte[] _initiatorEphemeralBytes;
    private readonly ulong _kdf;
    private readonly ulong _initiatorIdentity;

    /// <summary>
    /// Initializes X3DH responder parameters.
    /// </summary>
    /// <param name="kdf">KDF algorithm tag (CK_X3DH_KDF_TYPE).</param>
    /// <param name="identityId">Identity-key identifier bytes.</param>
    /// <param name="prekeyId">Prekey identifier bytes.</param>
    /// <param name="onetimeId">One-time prekey identifier bytes.</param>
    /// <param name="initiatorIdentity">Initiator's identity-key handle.</param>
    /// <param name="initiatorEphemeral">Initiator's ephemeral public-key bytes.</param>
    public CkmX3dhRespondParams(ulong kdf, ReadOnlySpan<byte> identityId, ReadOnlySpan<byte> prekeyId, ReadOnlySpan<byte> onetimeId, ulong initiatorIdentity, ReadOnlySpan<byte> initiatorEphemeral)
    {
        _identityIdBytes = identityId.IsEmpty ? [] : identityId.ToArray();
        _prekeyIdBytes = prekeyId.IsEmpty ? [] : prekeyId.ToArray();
        _onetimeIdBytes = onetimeId.IsEmpty ? [] : onetimeId.ToArray();
        _initiatorEphemeralBytes = initiatorEphemeral.IsEmpty ? [] : initiatorEphemeral.ToArray();
        _kdf = kdf;
        _initiatorIdentity = initiatorIdentity;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_X3DH_RESPOND_PARAMS
        {
            Kdf = (NativeCULong)_kdf,
            IdentityId = scope.Write(_identityIdBytes),
            PrekeyId = scope.Write(_prekeyIdBytes),
            OnetimeId = scope.Write(_onetimeIdBytes),
            InitiatorIdentity = (NativeCULong)_initiatorIdentity,
            InitiatorEphemeral = scope.Write(_initiatorEphemeralBytes),
        };
    }
}
