using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

/// <summary>
/// Requires ECDH parameters the library can read. The KDF they carry is judged separately, as a
/// <see cref="KeyAgreementKdfRequest"/> the session raises for every mechanism with
/// <see cref="CkmEcdh1DeriveParams"/>; any other parameter type (raw vendor bytes, none) would hide the
/// KDF from the policy, so it is refused here.
/// </summary>
internal sealed class Ecdh1DeriveParamsCheck : MechanismCheck
{
    public static readonly Ecdh1DeriveParamsCheck Instance = new();

    private protected override object DecisionKey => nameof(Ecdh1DeriveParamsCheck);

    private Ecdh1DeriveParamsCheck()
        : base("requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list")
    {
    }

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner) => mechanism.Parameters switch
    {
        CkmEcdh1DeriveParams => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(
            $"{MechanismNames.Describe(mechanism.Type)} requires CkmEcdh1DeriveParams, so that the key-agreement KDF it " +
            "applies to the shared secret (SP 800-56A Rev.3 §5.8) can be checked."),
    };
}
