using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("SoftHsm")]
public sealed class GenerateAesKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratedKey_HasNoWrapCapability() => GenerateAesKeyTestCases.Assert_GeneratedKey_HasNoWrapCapability(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesKeyEncryptionKey_WrapUnwrapOnly() => GenerateAesKeyTestCases.Assert_GeneratesKeyEncryptionKey_WrapUnwrapOnly(_backend);
}
