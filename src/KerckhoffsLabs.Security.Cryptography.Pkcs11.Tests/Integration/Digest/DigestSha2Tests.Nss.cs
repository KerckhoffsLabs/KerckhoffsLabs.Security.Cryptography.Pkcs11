using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>Cross-backend port of the SoftHSM2 SHA-2 digest integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class DigestSha2Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void Sha256_KnownAnswer() => DigestSha2TestCases.Assert_Sha256_KnownAnswer(_backend);

    [ConditionalFact(nameof(Available))]
    public void Sha384_OutputLength() => DigestSha2TestCases.Assert_Sha384_OutputLength(_backend);

    [ConditionalFact(nameof(Available))]
    public void Sha512_OutputLength() => DigestSha2TestCases.Assert_Sha512_OutputLength(_backend);
}
