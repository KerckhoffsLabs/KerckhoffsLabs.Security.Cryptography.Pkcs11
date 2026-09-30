using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// The shared allow-list evaluation engine behind every restrictive <see cref="ICryptoPolicy"/>
/// (<c>FipsOnly</c>, <c>SecureOnly</c>): evaluates a request against a policy-supplied
/// <see cref="PolicyCatalogue"/> and words the denial.
/// </summary>
/// <remarks>
/// A request matching an allowed entry for its operation (and passing that entry's parameter check) is
/// allowed. A request for an allowed item but another operation is denied as "allowed only for …".
/// Anything else is denied; the documented deny list only chooses between the "not allowed: {reason}"
/// and "not on the allow-list (not reviewed)" wordings and never changes a verdict.
/// </remarks>
internal static class CatalogueEvaluator
{
    /// <summary>Evaluates one request against a catalogue.</summary>
    /// <param name="catalogue">The policy's allow-list and rules.</param>
    /// <param name="policyName">The policy's <see cref="ICryptoPolicy.Name"/>, used in denial wording.</param>
    /// <param name="extensionHint">
    /// A sentence appended to an "unlisted mechanism" denial, pointing at the policy's extension point
    /// (the SecureOnly family's <c>WithAllowedMechanism</c>), or <see langword="null"/> for none. Never
    /// appended to hash, curve or KDF denials: the extension point adds mechanisms only.
    /// </param>
    /// <param name="request">The request being evaluated.</param>
    public static PolicyDecision Evaluate(PolicyCatalogue catalogue, string policyName, string? extensionHint, PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(catalogue);
        ArgumentNullException.ThrowIfNull(policyName);
        ArgumentNullException.ThrowIfNull(request);

        return request switch
        {
            MechanismUseRequest r => EvaluateMechanism(catalogue, policyName, extensionHint, r.Mechanism, r.Operation),
            HashUseRequest r => EvaluateHash(catalogue, policyName, r.Hash, r.Operation),
            RsaKeyGenerationRequest r => EvaluateRsaKeyGeneration(catalogue, policyName, extensionHint, r),
            EcKeyGenerationRequest r => EvaluateCurve(catalogue, policyName, r.Curve),
            KeyTemplateRequest r => catalogue.Rules.KeyTemplate(r),
            KeyAgreementKdfRequest r => EvaluateKdf(catalogue, policyName, r.Kdf),
            KeyAgreementKeyRequest r => EvaluateKeyAgreementKeyType(catalogue, policyName, r.KeyType),
            KeyMaterialExportRequest r => catalogue.Rules.KeyMaterialExport(r),
            _ => PolicyDecision.Deny($"{policyName} has no rule for {request.GetType().Name}."),
        };
    }

    private static PolicyDecision EvaluateMechanism(PolicyCatalogue c, string name, string? extensionHint, Mechanism mechanism, CryptoOperation operation)
    {
        CKM type = mechanism.Type;
        string item = MechanismNames.Describe(type);

        if (c.AllowedMechanisms.TryGetValue(type, out MechanismRule? rule))
            return Covers(rule, operation)
                ? rule.ParameterCheck?.Invoke(mechanism, operation) ?? PolicyDecision.Allow
                : DenyOperationNotPermitted(item, name, rule.Operations | rule.LegacyOperations, rule.Rationale, operation);

        if (c.AllowedVendorMechanisms.TryGetValue((ulong)type, out MechanismRule? vendorRule))
            return Covers(vendorRule, operation)
                ? vendorRule.ParameterCheck?.Invoke(mechanism, operation) ?? PolicyDecision.Allow
                : DenyOperationNotPermitted(item, name, vendorRule.Operations | vendorRule.LegacyOperations, vendorRule.Rationale, operation);

        return c.DocumentedRefusedMechanisms.TryGetValue(type, out DocumentedRefusal? refusal)
            ? DenyDocumented(item, refusal)
            : DenyUnlisted(item, name, extensionHint);
    }

    private static bool Covers(MechanismRule rule, CryptoOperation operation)
        => rule.Operations.Contains(operation) || rule.LegacyOperations.Contains(operation);

    private static PolicyDecision EvaluateHash(PolicyCatalogue c, string name, HashAlgorithmName hash, CryptoOperation operation)
    {
        string item = hash.Name ?? "(unnamed hash)";

        if (hash.Name is { } hashName)
        {
            if (c.AllowedHashes.TryGetValue(hashName, out AllowedHash? allowed))
                return allowed.Operations.Contains(operation)
                    ? PolicyDecision.Allow
                    : DenyOperationNotPermitted(item, name, allowed.Operations, allowed.Rationale, operation);

            if (c.DocumentedRefusedHashes.TryGetValue(hashName, out DocumentedRefusal? refusal))
                return DenyDocumented(item, refusal);
        }

        return DenyUnlisted(item, name, extensionHint: null);
    }

    private static PolicyDecision EvaluateCurve(PolicyCatalogue c, string name, Pkcs11ECCurve curve)
    {
        string item = curve.ToString();

        if (curve.Oid is { } oid)
        {
            if (c.AllowedCurves.ContainsKey(oid))
                return PolicyDecision.Allow;

            if (c.DocumentedRefusedCurves.TryGetValue(oid, out DocumentedRefusal? refusal))
                return DenyDocumented(item, refusal);
        }

        return DenyUnlisted(item, name, extensionHint: null);
    }

    private static PolicyDecision EvaluateKdf(PolicyCatalogue c, string name, CKD kdf)
    {
        if (c.AllowedKdfs.ContainsKey(kdf))
            return PolicyDecision.Allow;

        string item = kdf.ToString();
        return c.DocumentedRefusedKdfs.TryGetValue(kdf, out DocumentedRefusal? refusal)
            ? DenyDocumented(item, refusal)
            : DenyUnlisted(item, name, extensionHint: null);
    }

    private static PolicyDecision EvaluateKeyAgreementKeyType(PolicyCatalogue c, string name, CKK keyType)
    {
        if (c.AllowedKeyAgreementKeyTypes.ContainsKey(keyType))
            return PolicyDecision.Allow;

        string item = $"Key agreement with a {KeyTypeNames.Of(keyType)} key";
        return c.DocumentedRefusedKeyAgreementKeyTypes.TryGetValue(keyType, out DocumentedRefusal? refusal)
            ? DenyDocumented(item, refusal)
            : DenyUnlisted(item, name, extensionHint: null);
    }

    /// <summary>
    /// The only two mechanism types PKCS#11 defines for RSA key-pair generation. A
    /// <see cref="RsaKeyGenerationRequest"/> naming anything else is nonsensical — not merely unapproved —
    /// so this is checked by the shared evaluator itself, before any catalogue lookup, for every policy.
    /// </summary>
    private static bool IsRsaKeyPairGenerationMechanism(CKM mechanism)
        => mechanism is CKM.CKM_RSA_PKCS_KEY_PAIR_GEN or CKM.CKM_RSA_X9_31_KEY_PAIR_GEN;

    private static PolicyDecision EvaluateRsaKeyGeneration(PolicyCatalogue c, string name, string? extensionHint, RsaKeyGenerationRequest request)
    {
        if (!IsRsaKeyPairGenerationMechanism(request.Mechanism))
            return PolicyDecision.Deny(
                $"{MechanismNames.Of(request.Mechanism)} is not an RSA key-pair-generation mechanism " +
                "(expected CKM_RSA_PKCS_KEY_PAIR_GEN or CKM_RSA_X9_31_KEY_PAIR_GEN).");

        string item = MechanismNames.Of(request.Mechanism);

        if (c.AllowedMechanisms.TryGetValue(request.Mechanism, out MechanismRule? rule))
            return Covers(rule, CryptoOperation.GenerateKeyPair)
                ? c.Rules.RsaKeyGeneration(request)
                : DenyOperationNotPermitted(item, name, rule.Operations | rule.LegacyOperations, rule.Rationale, CryptoOperation.GenerateKeyPair);

        return c.DocumentedRefusedMechanisms.TryGetValue(request.Mechanism, out DocumentedRefusal? refusal)
            ? DenyDocumented(item, refusal)
            : DenyUnlisted(item, name, extensionHint);
    }

    private static PolicyDecision DenyDocumented(string item, DocumentedRefusal refusal)
    {
        // A documented reason is a full sentence ending with its own period.
        string tail = refusal.Alternative is { } alternative ? $" Use {alternative}." : "";
        return PolicyDecision.Deny($"{item} is not allowed: {refusal.Reason}{tail}");
    }

    private static PolicyDecision DenyUnlisted(string item, string policyName, string? extensionHint)
    {
        string reason = $"{item} is not on the {policyName} allow-list (not reviewed).";
        return PolicyDecision.Deny(extensionHint is null ? reason : $"{reason} {extensionHint}");
    }

    /// <summary>
    /// Denies a request for an item that <em>is</em> on the allow-list, but not for the requested
    /// operation. It must not be worded as "not reviewed" — it was reviewed and deliberately restricted —
    /// and never carries the extension hint.
    /// </summary>
    private static PolicyDecision DenyOperationNotPermitted(
        string item, string policyName, CryptoOperations permittedOperations, string rationale, CryptoOperation requestedOperation)
        => PolicyDecision.Deny(
            $"{item} is allowed under {policyName} only for {FormatOperations(permittedOperations)}; {requestedOperation} is not. {rationale}");

    /// <summary>
    /// Renders a <see cref="CryptoOperations"/> set as its member names, in <see cref="CryptoOperation"/>
    /// declaration order. Internal (not private): also used by <c>PolicyCatalogueMarkdown</c> so the
    /// generated catalogue documentation formats operations identically to denial wording.
    /// </summary>
    internal static string FormatOperations(CryptoOperations operations)
        => string.Join(", ", Enum.GetValues<CryptoOperation>().Where(op => operations.Contains(op)));
}

/// <summary>
/// A <see cref="PolicyRequest"/> kind the shared evaluator does not recognise. Real policies never
/// construct this; it exists solely to exercise <see cref="CatalogueEvaluator"/>'s default-deny arm
/// from the test assembly (visible via <c>InternalsVisibleTo</c>) — <see cref="PolicyRequest"/>'s
/// constructor is <see langword="private protected"/>, so only a type declared in this assembly can be
/// one.
/// </summary>
internal sealed record UnrecognizedPolicyRequest : PolicyRequest
{
    internal override string Describe() => "an unrecognized request kind";
}
