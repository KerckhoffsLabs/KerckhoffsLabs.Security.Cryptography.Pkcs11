using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

internal sealed record KdfPrfWording(
    string Description,
    string MissingParameters,
    Func<string, string> NotAllowed,
    Func<string, DocumentedRefusal, string> DocumentedRefusal);

/// <summary>A KDF family whose parameters name a PRF: how to read it, and how the docs label the family.</summary>
internal sealed class KdfPrfFamily(string documentationLabel, string shortName, Func<MechanismParameters?, string?> readPrf)
{
    public static readonly KdfPrfFamily Pbkdf2 = new("PBKDF2 (CKM_PKCS5_PBKD2)", "PBKDF2",
        p => p is CkmPkcs5Pbkd2Params x ? x.Prf.ToString() : null);
    public static readonly KdfPrfFamily Sp800108 = new("SP 800-108 (CKM_SP800_108_*_KDF)", "SP 800-108",
        p => p is CkmSp800108KdfParams x ? x.PrfType.ToString() : null);
    public static readonly KdfPrfFamily Hkdf = new("HKDF (CKM_HKDF_DERIVE)", "HKDF",
        p => p is CkmHkdfParams x ? x.PrfHashMechanism.ToString() : null);

    /// <summary>The key under which the generated docs list this family's allowed PRFs.</summary>
    public string DocumentationLabel => documentationLabel;

    /// <summary>The family's name in denial messages.</summary>
    public string ShortName => shortName;

    /// <summary>The PRF the parameters name, as its <c>ToString()</c>; <see langword="null"/> for any other parameter type.</summary>
    public string? ReadPrf(MechanismParameters? parameters) => readPrf(parameters);
}

/// <summary>
/// Requires a KDF's parameters to name an allowed PRF. A PRF on the owning policy's documented PRF refusal
/// list is denied with that reason and alternative.
/// </summary>
internal sealed class KdfPrfCheck(KdfPrfFamily family, FrozenSet<string> allowed, KdfPrfWording wording) : MechanismCheck(wording.Description)
{
    private protected override object DecisionKey => $"{family.DocumentationLabel}|{SetKey(allowed)}";

    public KdfPrfFamily Family => family;

    public FrozenSet<string> AllowedPrfs => allowed;

    internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner)
    {
        string? prf = family.ReadPrf(mechanism.Parameters);
        if (prf is null)
            return PolicyDecision.Deny(wording.MissingParameters);
        if (allowed.Contains(prf))
            return PolicyDecision.Allow;
        return owner.DocumentedRefusedPrfs.TryGetValue(prf, out DocumentedRefusal? refusal)
            ? PolicyDecision.Deny(wording.DocumentedRefusal(prf, refusal))
            : PolicyDecision.Deny(wording.NotAllowed(prf));
    }
}
