using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.NistApproved"/> over FreeHSM — thin wrapper over <see cref="NistApprovedPolicyTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class NistApprovedPolicyTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void AesGcm_RoundTrips() =>
        NistApprovedPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPss_Signs() =>
        NistApprovedPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        NistApprovedPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        NistApprovedPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
