using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

internal sealed record OaepHashWording(string Description, string MissingParameters, Func<CKM, string> DisallowedHash);

/// <summary>Requires <see cref="CkmRsaPkcsOaepParams"/> naming one of a set of hashes.</summary>
internal sealed class OaepHashCheck(FrozenSet<CKM> allowed, OaepHashWording wording) : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => SetKey(allowed);

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) => mechanism.Parameters switch
    {
        CkmRsaPkcsOaepParams p when allowed.Contains(p.HashAlg) => PolicyDecision.Allow,
        CkmRsaPkcsOaepParams p => PolicyDecision.Deny(wording.DisallowedHash(p.HashAlg)),
        _ => PolicyDecision.Deny(wording.MissingParameters),
    };
}
