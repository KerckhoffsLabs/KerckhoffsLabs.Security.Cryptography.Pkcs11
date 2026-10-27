using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

/// <summary>
/// A floor on the AES-CCM MAC, read from <see cref="CkmAesCcmParams"/> or <see cref="CkmCcmMessageParams"/>;
/// a mechanism without parameters passes, as for AES-GCM.
/// </summary>
internal sealed class CcmMacLengthCheck(int minimumBits, AeadTagWording wording) : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => minimumBits;

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) => mechanism.Parameters switch
    {
        CkmAesCcmParams p => Require(8 * p.MacLength),
        CkmCcmMessageParams p => Require(8 * p.MacLength),
        null when !mechanism.HasRawParameter => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(wording.WrongParameterType),
    };

    private PolicyDecision Require(int macBits) =>
        macBits >= minimumBits ? PolicyDecision.Allow : PolicyDecision.Deny(wording.TooShort(macBits));
}
