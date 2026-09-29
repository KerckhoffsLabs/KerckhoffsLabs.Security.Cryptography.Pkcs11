using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>The parameter check the restrictive policies share for ECDH key agreement.</summary>
internal static class KeyAgreementParameterChecks
{
    /// <summary>What <see cref="RequireEcdh1DeriveParams"/> requires, for the generated catalogue documentation.</summary>
    public const string Ecdh1DeriveDescription =
        "requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list";

    /// <summary>
    /// Requires ECDH parameters the library can read. The KDF they carry is judged separately, as a
    /// <see cref="KeyAgreementKdfRequest"/> the session raises for every mechanism with
    /// <see cref="CkmEcdh1DeriveParams"/>; any other parameter type (raw vendor bytes, none) would hide the
    /// KDF from the policy, so it is refused here.
    /// </summary>
    public static PolicyDecision RequireEcdh1DeriveParams(Mechanism m, CryptoOperation op) => m.Parameters switch
    {
        CkmEcdh1DeriveParams => PolicyDecision.Allow,
        _ => PolicyDecision.Deny(
            $"{MechanismNames.Describe(m.Type)} requires CkmEcdh1DeriveParams, so that the key-agreement KDF it " +
            "applies to the shared secret (SP 800-56A Rev.3 §5.8) can be checked."),
    };
}
