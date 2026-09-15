using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>RSA PKCS#1 v1.5 gate against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class DecryptRsaTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
