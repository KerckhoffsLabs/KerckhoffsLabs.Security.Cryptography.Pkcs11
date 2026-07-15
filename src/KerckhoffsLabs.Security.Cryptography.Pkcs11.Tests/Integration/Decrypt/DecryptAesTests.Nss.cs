using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>Cross-backend port of the SoftHSM2 AES decrypt integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class DecryptAesTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault() => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [ConditionalFact(nameof(Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue() => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
