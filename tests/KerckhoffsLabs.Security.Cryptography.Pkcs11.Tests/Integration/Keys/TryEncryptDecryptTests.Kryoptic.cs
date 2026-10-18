using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary><see cref="Pkcs11Key.TryEncrypt"/> and <see cref="Pkcs11Key.TryDecrypt"/> over Kryoptic — thin wrapper over <see cref="TryEncryptDecryptTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class TryEncryptDecryptTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Gcm_RoundTrips_IntoExactDestinations() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_RoundTrips_IntoExactDestinations);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Gcm_IntoLargerDestinations_WritesTheResultLength() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_Gcm_IntoLargerDestinations_WritesTheResultLength);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void OverlappingDestination_Throws() => TryEncryptDecryptTestCases.WithAesKey(_backend, CKM.CKM_AES_GCM, TryEncryptDecryptTestCases.Assert_OverlappingDestination_Throws);
}
