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

    // No Ed448 round-trip here: NSS's C_Sign for Ed448 returns CKR_MECHANISM_PARAM_INVALID —
    // it requires a CK_EDDSA_PARAMS structure for Ed448, whereas the wrapper drives pure EdDSA with a
    // bare CKM_EDDSA mechanism (which SoftHSM and NSS both accept for Ed25519). Ed448 stays
    // covered on SoftHSM (SignEdDsaTests_SoftHsm.Ed448_RoundTrip).
}
