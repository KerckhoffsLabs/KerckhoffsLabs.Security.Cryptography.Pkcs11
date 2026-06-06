using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>AES decrypt gate tests against SoftHSM2.</summary>
[Collection("SoftHsm")]
public sealed class DecryptAesTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesEcb_AllowedWhenAllowInsecureTrue_SoftHsm()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
