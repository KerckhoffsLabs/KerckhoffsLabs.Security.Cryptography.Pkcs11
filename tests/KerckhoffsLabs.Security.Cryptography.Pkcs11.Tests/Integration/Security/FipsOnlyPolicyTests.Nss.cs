using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.FipsOnly"/> over NSS softoken — thin wrapper over <see cref="FipsOnlyPolicyTestCases"/>.</summary>
[Collection("Nss")]
public sealed class FipsOnlyPolicyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesGcm_RoundTrips()
    {
        _backend.RequireClassicAesGcm();
        FipsOnlyPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPss_Signs() =>
        FipsOnlyPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        FipsOnlyPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        FipsOnlyPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
