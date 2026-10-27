using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

internal sealed record RsaPssWording(
    string Description,
    string MissingParameters,
    string WrongParameterType,
    Func<CKM, string> DisallowedHash,
    Func<CKM, CryptoOperation, string> VerifyOnlyHash,
    Func<int, int, CKM, string> SaltTooLong);

/// <summary>
/// RSA-PSS parameters: an allowed hash (or a verify-only one, to verify), with a salt no longer than its
/// output. Raw <c>CKM_RSA_PKCS_PSS</c> requires the parameters; a hash-bound PSS mechanism checks them only
/// when given. Raw parameter bytes it cannot read are refused, since passing them would skip the hash and salt checks.
/// </summary>
internal sealed class RsaPssCheck(FrozenSet<CKM> allowed, FrozenSet<CKM> verifyOnly, bool parametersRequired, RsaPssWording wording)
    : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => $"{SetKey(allowed)}|{SetKey(verifyOnly)}|{parametersRequired}";

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) => mechanism.Parameters switch
    {
        CkmRsaPkcsPssParams p => CheckParameters(p, operation),
        null when !parametersRequired && !mechanism.HasRawParameter => PolicyDecision.Allow,
        _ when parametersRequired => PolicyDecision.Deny(wording.MissingParameters),
        _ => PolicyDecision.Deny(wording.WrongParameterType),
    };

    private PolicyDecision CheckParameters(CkmRsaPkcsPssParams p, CryptoOperation operation)
    {
        if (!allowed.Contains(p.HashAlg) && !verifyOnly.Contains(p.HashAlg))
            return PolicyDecision.Deny(wording.DisallowedHash(p.HashAlg));
        if (!allowed.Contains(p.HashAlg) && operation != CryptoOperation.Verify)
            return PolicyDecision.Deny(wording.VerifyOnlyHash(p.HashAlg, operation));
        int hashLength = HashOutputLengths.Of(p.HashAlg);
        if (p.SaltLength > hashLength)
            return PolicyDecision.Deny(wording.SaltTooLong(p.SaltLength, hashLength, p.HashAlg));
        return PolicyDecision.Allow;
    }
}
