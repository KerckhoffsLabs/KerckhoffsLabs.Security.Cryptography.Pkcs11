using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA sign tests, run against NSS. These generate the
/// EdDSA key pair on the token (NSS rejects *importing* EdDSA keys, but advertises
/// CKM_EC_EDWARDS_KEY_PAIR_GEN), so the round-trip exercises on-token keygen + sign + verify. Gated on
/// the live mechanism list.
/// </summary>
[Collection("Nss")]
public sealed class SignEdDsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // NSS's CKM_EDDSA needs a CK_EDDSA_PARAMS the shared bare-parameter case does not pass; skip.
    public static bool EdDsa => NssBackendFixture.EdDsaAvailable;

    private void RequireEdDsa()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            throw new SkipTestException("NSS: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
    }

    [ConditionalFact(nameof(EdDsa))]
    public void Ed25519_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);
    }

    // NSS's C_GenerateKeyPair rejects the id-Ed448 OID (1.3.101.113) as CKA_EC_PARAMS for
    // CKM_EC_EDWARDS_KEY_PAIR_GEN with CKR_DOMAIN_PARAMS_INVALID -- confirmed in CI
    // (KerckhoffsLabs.Security.Cryptography.Pkcs11 run 34634992368): its EdDSA key generation
    // supports Ed25519 only. This is a genuine key-generation gap, distinct from (and upstream
    // of) the bare-CKM_EDDSA-vs-CK_EDDSA_PARAMS signing issue Assert_Ed448_RoundTrip's explicit
    // params already fix elsewhere (Kryoptic, opencryptoki) -- NSS never reaches signing at all.
    public static bool SupportsEd448KeyGeneration => false;

    [ConditionalFact(nameof(SupportsEd448KeyGeneration))]
    public void Ed448_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
    }
}
