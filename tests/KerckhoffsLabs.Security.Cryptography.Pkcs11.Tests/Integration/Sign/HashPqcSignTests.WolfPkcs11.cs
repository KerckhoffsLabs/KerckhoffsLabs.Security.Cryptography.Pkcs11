using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over wolfPKCS11 — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class HashPqcSignTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HashSlhDsaSha256_SignsAndVerifies() =>
        HashPqcSignTestCases.Assert_HashSlhDsaSha256_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend);
}
