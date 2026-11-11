using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// <see cref="Pkcs11Key.TryEncrypt"/> and <see cref="Pkcs11Key.TryDecrypt"/> over NSS — thin wrapper over
/// <see cref="TryEncryptDecryptTestCases"/>. The cases use classic AES-GCM, which NSS before 3.52 cannot read.
/// </summary>
[Collection("Nss")]
public sealed class TryEncryptDecryptTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Gcm_RoundTrips_IntoExactDestinations()
    {
        _backend.RequireClassicAesGcm();
        TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_RoundTrips_IntoExactDestinations);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing()
    {
        _backend.RequireClassicAesGcm();
        TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing()
    {
        _backend.RequireClassicAesGcm();
        TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Gcm_IntoLargerDestinations_WritesTheResultLength()
    {
        _backend.RequireClassicAesGcm();
        TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_IntoLargerDestinations_WritesTheResultLength);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void OverlappingDestination_Throws()
    {
        _backend.RequireClassicAesGcm();
        TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_OverlappingDestination_Throws);
    }
}
