using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.FipsOnly"/> over BouncyHsm — thin wrapper over <see cref="FipsOnlyPolicyTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class FipsOnlyPolicyTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_RoundTrips() =>
        FipsOnlyPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPss_Signs() =>
        FipsOnlyPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        FipsOnlyPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        FipsOnlyPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
