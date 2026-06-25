using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over OpenCryptoki — thin wrapper over <see cref="HMACPkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class HMACPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalTheory(nameof(Available))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
        => HMACPkcs11TestCases.Assert_ComputeHash_DeterministicForSameKeyAndInput(_backend, hashName, expectedLen);

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => HMACPkcs11TestCases.Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => HMACPkcs11TestCases.Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_UnsupportedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NoNamedHash_Throws() => HMACPkcs11TestCases.Assert_Ctor_NoNamedHash_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_HmacSha256_KnownAnswer() => HMACPkcs11TestCases.Assert_ComputeHash_HmacSha256_KnownAnswer(_backend);
}
