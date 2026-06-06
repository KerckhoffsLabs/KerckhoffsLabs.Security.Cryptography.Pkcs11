using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("SoftHsm")]
public sealed class GenerateRsaKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);
}
