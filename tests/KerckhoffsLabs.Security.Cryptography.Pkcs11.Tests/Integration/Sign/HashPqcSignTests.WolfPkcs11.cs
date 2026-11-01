using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over wolfPKCS11 — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class HashPqcSignTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(HashPqcSignTestCases.CombinedHashSlhDsaMechanisms), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_SignsAndVerifies(CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_SignsAndVerifies(_backend, combined);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(HashPqcSignTestCases.ExplicitHashSlhDsaPairs), MemberType = typeof(HashPqcSignTestCases))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined(CKM hash, CKM combined) =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend, hash, combined);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(HashPqcSignTestCases.CombinedHashMlDsaMechanisms), MemberType = typeof(HashPqcSignTestCases))]
    public void HashMlDsa_SignsAndVerifies(CKM combined) =>
        HashPqcSignTestCases.Assert_HashMlDsa_SignsAndVerifies(_backend, combined);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(HashPqcSignTestCases.ExplicitHashMlDsaPairs), MemberType = typeof(HashPqcSignTestCases))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined(CKM hash, CKM combined) =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend, hash, combined);
}
