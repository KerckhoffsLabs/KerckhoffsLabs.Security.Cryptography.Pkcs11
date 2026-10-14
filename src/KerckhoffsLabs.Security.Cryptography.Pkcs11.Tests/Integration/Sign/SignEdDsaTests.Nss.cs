using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA sign tests, run against NSS. These generate the
/// EdDSA key pair on the token (NSS rejects *importing* EdDSA keys, but advertises
/// CKM_EC_EDWARDS_KEY_PAIR_GEN), so the round-trip exercises on-token keygen + sign + verify. Gated on
/// the live mechanism list (CKM_EDDSA from NSS 3.125). NSS can only be signed with through a buffer of
/// exactly 64 bytes, which KnownOutputLength.OfSignature sizes it at.
/// </summary>
[Collection("Nss")]
public sealed class SignEdDsaTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    private void RequireEdDsa()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("NSS: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ed25519_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);
    }

    // NSS's C_GenerateKeyPair rejects the id-Ed448 OID (1.3.101.113) as CKA_EC_PARAMS for
    // CKM_EC_EDWARDS_KEY_PAIR_GEN with CKR_DOMAIN_PARAMS_INVALID -- confirmed in CI
    // (KerckhoffsLabs.Security.Cryptography.Pkcs11 run 34634992368): its EdDSA key generation
    // supports Ed25519 only, and its freebl signs nothing but Ed25519.
    public static bool SupportsEd448KeyGeneration => false;

    [Fact(SkipUnless = nameof(SupportsEd448KeyGeneration), Skip = "Requires " + nameof(SupportsEd448KeyGeneration))]
    public void Ed448_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
    }
}
