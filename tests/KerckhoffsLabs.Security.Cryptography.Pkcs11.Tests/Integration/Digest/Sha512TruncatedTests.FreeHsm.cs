using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>SHA-512/224 and SHA-512/256 over FreeHSM — thin wrapper over <see cref="Sha512TruncatedTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class Sha512TruncatedTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Sha512_224_Kat() =>
        Sha512TruncatedTestCases.Assert_Sha512_224_Kat(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Sha512_256_Kat() =>
        Sha512TruncatedTestCases.Assert_Sha512_256_Kat(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HmacSha512_224_Kat() =>
        Sha512TruncatedTestCases.Assert_HmacSha512_224_Kat(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HmacSha512_256_Kat() =>
        Sha512TruncatedTestCases.Assert_HmacSha512_256_Kat(_backend);
}
