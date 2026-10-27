using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

internal sealed record AeadTagWording(string Description, Func<int, string> TooShort, string WrongParameterType);

/// <summary>
/// A floor on the AES-GCM tag, read from <see cref="CkmAesGcmParams"/> or <see cref="CkmGcmMessageParams"/>.
/// A mechanism without parameters passes: the message API is judged with its per-message parameters, and a
/// single-part call without them fails at the token. Parameters it cannot read are refused.
/// </summary>
internal sealed class GcmTagLengthCheck(int minimumBits, AeadTagWording wording) : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => minimumBits;

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) => mechanism.Parameters switch
    {
        CkmAesGcmParams p => Require(p.TagBits),
        CkmGcmMessageParams p => Require(8 * p.TagLength),
        null when !mechanism.HasRawParameter => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(wording.WrongParameterType),
    };

    private PolicyDecision Require(int tagBits) =>
        tagBits >= minimumBits ? PolicyDecision.Allow : PolicyDecision.Deny(wording.TooShort(tagBits));
}
