using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 EC key-pair generation integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class GenerateEcKeyPairTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);
}
