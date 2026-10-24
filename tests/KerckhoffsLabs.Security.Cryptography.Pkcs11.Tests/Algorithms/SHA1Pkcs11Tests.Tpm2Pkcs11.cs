using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA1Pkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="SHA1Pkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class SHA1Pkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_GatedByDefault_Throws() => SHA1Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => SHA1Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
