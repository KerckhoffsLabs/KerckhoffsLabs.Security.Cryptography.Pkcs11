using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over Craton HSM — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class HashPqcSignTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(HashPqcSignTestCases.CombinedHashSlhDsaMechanisms), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_SignsAndVerifies(CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_SignsAndVerifies(_backend, combined);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(HashPqcSignTestCases.ExplicitHashSlhDsaPairs), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined(CKM hash, CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend, hash, combined);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend);
}
