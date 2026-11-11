using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary><see cref="Pkcs11Key.TryEncrypt"/> and <see cref="Pkcs11Key.TryDecrypt"/> over SoftHSMv2 — thin wrapper over <see cref="TryEncryptDecryptTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class TryEncryptDecryptTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Gcm_RoundTrips_IntoExactDestinations() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_RoundTrips_IntoExactDestinations);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Gcm_IntoLargerDestinations_WritesTheResultLength() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_IntoLargerDestinations_WritesTheResultLength);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void OverlappingDestination_Throws() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_OverlappingDestination_Throws);
}
