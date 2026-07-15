using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 RSA PKCS#1 sign gate integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class SignRsaPkcsTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void SignRsaPkcs1V15_GatedByDefault() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
