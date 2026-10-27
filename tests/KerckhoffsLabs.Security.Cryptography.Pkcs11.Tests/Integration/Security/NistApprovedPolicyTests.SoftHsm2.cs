using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.NistApproved"/> over SoftHSM2 — thin wrapper over <see cref="NistApprovedPolicyTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class NistApprovedPolicyTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesGcm_RoundTrips() =>
        NistApprovedPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaPss_Signs() =>
        NistApprovedPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        NistApprovedPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        NistApprovedPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
