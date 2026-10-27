using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.NistApproved"/> over opencryptoki — thin wrapper over <see cref="NistApprovedPolicyTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class NistApprovedPolicyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesGcm_RoundTrips() =>
        NistApprovedPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaPss_Signs() =>
        NistApprovedPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        NistApprovedPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        NistApprovedPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
