using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA1Pkcs11 over BouncyHsm — thin wrapper over <see cref="SHA1Pkcs11TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SHA1Pkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_GatedByDefault_Throws() => SHA1Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => SHA1Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
