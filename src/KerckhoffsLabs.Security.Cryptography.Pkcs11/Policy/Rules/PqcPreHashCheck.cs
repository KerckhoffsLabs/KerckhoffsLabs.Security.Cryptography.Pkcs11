using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

internal sealed record PqcPreHashWording(string Description, string Denial);

/// <summary>Requires <see cref="CkmHashPqcSignParams"/> naming one of a set of pre-hashes.</summary>
internal sealed class PqcPreHashCheck(FrozenSet<CKM> allowed, PqcPreHashWording wording) : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => SetKey(allowed);

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) =>
        mechanism.Parameters is CkmHashPqcSignParams p && allowed.Contains(p.Hash)
            ? PolicyDecision.Allow
            : PolicyDecision.Deny(wording.Denial);
}
