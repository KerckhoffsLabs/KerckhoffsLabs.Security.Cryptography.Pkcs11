using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>AES decrypt gate tests against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class DecryptAesTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_ThrowsCryptoPolicyViolationException_ByDefault()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
