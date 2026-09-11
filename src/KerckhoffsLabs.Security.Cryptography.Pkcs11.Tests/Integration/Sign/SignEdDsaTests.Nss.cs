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

    // Ed448_RoundTrip is gated on Available (not EdDsa/SupportsEdDsa): that flag exists
    // specifically because NSS rejects a *bare* CKM_EDDSA sign (the Ed25519 case above), not
    // because Ed448 itself is unsupported. Assert_Ed448_RoundTrip passes an explicit
    // CK_EDDSA_PARAMS, which is exactly the form NSS requires.
    [ConditionalFact(nameof(Available))]
    public void Ed448_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
    }
}
