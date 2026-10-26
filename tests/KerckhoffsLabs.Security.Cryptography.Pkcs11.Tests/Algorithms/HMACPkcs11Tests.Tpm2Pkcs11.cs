using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="HMACPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class HMACPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
        => HMACPkcs11TestCases.Assert_ComputeHash_DeterministicForSameKeyAndInput(_backend, hashName, expectedLen);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_Sha224_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_Sha224_WithoutAllowInsecure_Throws() => HMACPkcs11TestCases.Assert_ComputeHash_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => HMACPkcs11TestCases.Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ctor_UnsupportedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ctor_NoNamedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_NoNamedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.LongHmacKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "A TPM holds at most 128 bytes of key; RFC 4231 case 6 uses 131")]
    public void ComputeHash_HmacSha256_KnownAnswer() => HMACPkcs11TestCases.Assert_ComputeHash_HmacSha256_KnownAnswer(_backend);
}
