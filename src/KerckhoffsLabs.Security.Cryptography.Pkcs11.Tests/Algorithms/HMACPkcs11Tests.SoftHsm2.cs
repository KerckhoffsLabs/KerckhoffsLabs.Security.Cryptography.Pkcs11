using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over SoftHsm — thin wrapper over <see cref="HMACPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class HMACPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
        => HMACPkcs11TestCases.Assert_ComputeHash_DeterministicForSameKeyAndInput(_backend, hashName, expectedLen);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_Sha224_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_Sha224_WithoutAllowInsecure_Throws() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => HMACPkcs11TestCases.Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Ctor_UnsupportedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Ctor_NoNamedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_NoNamedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_HmacSha256_KnownAnswer() => HMACPkcs11TestCases.Assert_ComputeHash_HmacSha256_KnownAnswer(_backend);
}
