using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MD5Pkcs11 over wolfPKCS11 — thin wrapper over <see cref="MD5Pkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class MD5Pkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_GatedByDefault_Throws() => MD5Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => MD5Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
