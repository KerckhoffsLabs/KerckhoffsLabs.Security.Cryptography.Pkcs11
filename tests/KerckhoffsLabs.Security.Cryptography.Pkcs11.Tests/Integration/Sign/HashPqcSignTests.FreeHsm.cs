using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over FreeHSM — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class HashPqcSignTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(HashPqcSignTestCases.CombinedHashSlhDsaMechanisms), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_SignsAndVerifies(CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_SignsAndVerifies(_backend, combined);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(HashPqcSignTestCases.ExplicitHashSlhDsaPairs), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined(CKM hash, CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend, hash, combined);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend);
}
