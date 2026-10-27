using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.NistApproved"/> over Kryoptic — thin wrapper over <see cref="NistApprovedPolicyTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class NistApprovedPolicyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesGcm_RoundTrips() =>
        NistApprovedPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RsaPss_Signs() =>
        NistApprovedPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        NistApprovedPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        NistApprovedPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
