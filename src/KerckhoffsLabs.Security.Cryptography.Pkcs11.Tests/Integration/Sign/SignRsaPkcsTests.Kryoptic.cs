using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

[Collection("Kryoptic")]
public sealed class SignRsaPkcsTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignRsaPkcs1V15_GatedByDefault()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
