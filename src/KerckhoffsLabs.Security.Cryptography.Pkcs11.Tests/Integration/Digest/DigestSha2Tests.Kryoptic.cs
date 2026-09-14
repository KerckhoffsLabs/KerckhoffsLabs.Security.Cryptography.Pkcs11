using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>Cross-backend port of the SoftHSM2 SHA-2 digest integration tests, run against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class DigestSha2Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Sha256_KnownAnswer() => DigestSha2TestCases.Assert_Sha256_KnownAnswer(_backend);

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Sha384_OutputLength() => DigestSha2TestCases.Assert_Sha384_OutputLength(_backend);

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Sha512_OutputLength() => DigestSha2TestCases.Assert_Sha512_OutputLength(_backend);
}
