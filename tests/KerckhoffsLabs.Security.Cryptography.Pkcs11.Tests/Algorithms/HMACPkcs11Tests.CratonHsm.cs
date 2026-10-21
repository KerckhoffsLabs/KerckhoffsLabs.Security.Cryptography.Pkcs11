using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over Craton HSM — thin wrapper over <see cref="HMACPkcs11TestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class HMACPkcs11Tests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
        => HMACPkcs11TestCases.Assert_ComputeHash_DeterministicForSameKeyAndInput(_backend, hashName, expectedLen);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ComputeHash_Sha224_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ComputeHash_Sha224_WithoutAllowInsecure_Throws() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => HMACPkcs11TestCases.Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_UnsupportedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_NoNamedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_NoNamedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ComputeHash_HmacSha256_KnownAnswer() => HMACPkcs11TestCases.Assert_ComputeHash_HmacSha256_KnownAnswer(_backend);
}
