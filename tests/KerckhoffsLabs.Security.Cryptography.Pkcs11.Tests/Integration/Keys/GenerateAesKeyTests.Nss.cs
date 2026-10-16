using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 AES key generation integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class GenerateAesKeyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratedKey_HasNoWrapCapability() => GenerateAesKeyTestCases.Assert_GeneratedKey_HasNoWrapCapability(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratesKeyEncryptionKey_WrapUnwrapOnly() => GenerateAesKeyTestCases.Assert_GeneratesKeyEncryptionKey_WrapUnwrapOnly(_backend);
}
