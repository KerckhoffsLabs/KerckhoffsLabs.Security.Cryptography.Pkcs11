using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over BouncyHsm — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class HashPqcSignTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashSlhDsaSha256_SignsAndVerifies() =>
        HashPqcSignTestCases.Assert_HashSlhDsaSha256_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend);
}
