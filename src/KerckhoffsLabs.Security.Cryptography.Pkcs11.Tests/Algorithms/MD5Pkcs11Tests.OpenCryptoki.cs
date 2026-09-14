using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MD5Pkcs11 over opencryptoki — thin wrapper over <see cref="MD5Pkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class MD5Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_GatedByDefault_Throws() => MD5Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => MD5Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
