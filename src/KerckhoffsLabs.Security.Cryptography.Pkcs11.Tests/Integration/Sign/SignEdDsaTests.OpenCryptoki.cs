using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Cross-backend port of the SoftHSM2 EdDSA sign tests, run against opencryptoki. These generate the
/// EdDSA key pair on the token (opencryptoki rejects *importing* EdDSA keys, but advertises
/// CKM_EC_EDWARDS_KEY_PAIR_GEN), so the round-trip exercises on-token keygen + sign + verify. Gated on
/// the live mechanism list.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SignEdDsaTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private void RequireEdDsa()
    {
        if (!_backend.Supports(CKM.CKM_EDDSA) || !_backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            throw new SkipTestException("opencryptoki: EdDSA (CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN) not available");
    }

    [ConditionalFact(nameof(Available))]
    public void Ed25519_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);
    }

    // No Ed448 round-trip here: opencryptoki's C_Sign for Ed448 returns CKR_MECHANISM_PARAM_INVALID —
    // it requires a CK_EDDSA_PARAMS structure for Ed448, whereas the wrapper drives pure EdDSA with a
    // bare CKM_EDDSA mechanism (which SoftHSM and opencryptoki both accept for Ed25519). Ed448 stays
    // covered on SoftHSM (SignEdDsaTests_SoftHsm.Ed448_RoundTrip).
}
