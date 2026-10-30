using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over wolfPKCS11 — thin wrapper over <see cref="HMACPkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class HMACPkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
        => HMACPkcs11TestCases.Assert_ComputeHash_DeterministicForSameKeyAndInput(_backend, hashName, expectedLen);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_Sha224_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_Sha224_WithoutAllowInsecure_Throws() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => HMACPkcs11TestCases.Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ctor_UnsupportedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ctor_NoNamedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_NoNamedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ComputeHash_HmacSha256_KnownAnswer() => HMACPkcs11TestCases.Assert_ComputeHash_HmacSha256_KnownAnswer(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(HMACPkcs11TestCases.Sha3KeySizes), MemberType = typeof(HMACPkcs11TestCases))]
    public void Sha3_ComputeAndTryComputeHash_MatchBcl(string hashName, int keyLength)
        => HMACPkcs11TestCases.Assert_Sha3_ComputeAndTryComputeHash_MatchBcl(_backend, hashName, keyLength);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HmacSha3_256_WycheproofVectors() => HMACPkcs11TestCases.Assert_HmacSha3_256_WycheproofVectors(_backend);
}
