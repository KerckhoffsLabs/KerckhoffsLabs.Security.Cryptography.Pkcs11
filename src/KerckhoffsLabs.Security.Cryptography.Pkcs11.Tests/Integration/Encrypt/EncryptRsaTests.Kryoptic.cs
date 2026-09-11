using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA PKCS#1 v1.5 gate against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class EncryptRsaTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Kryoptic()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
