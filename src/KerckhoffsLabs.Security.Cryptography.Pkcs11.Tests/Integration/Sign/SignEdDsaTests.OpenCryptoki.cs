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

    [ConditionalFact(nameof(Available))]
    public void Ed448_RoundTrip()
    {
        RequireEdDsa();
        SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
    }
}
