using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Pre-hash PQC signing over tpm2-pkcs11 — thin wrapper over <see cref="HashPqcSignTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class HashPqcSignTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void HashSlhDsaSha256_SignsAndVerifies() =>
        HashPqcSignTestCases.Assert_HashSlhDsaSha256_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void HashSlhDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void HashMlDsa_ExplicitHash_AgreesWithCombined() =>
        HashPqcSignTestCases.Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(_backend);
}
