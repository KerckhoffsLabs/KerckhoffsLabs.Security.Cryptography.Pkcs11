using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>AES decrypt gate tests against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class DecryptAesTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;


    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_Kryoptic()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue_Kryoptic()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
