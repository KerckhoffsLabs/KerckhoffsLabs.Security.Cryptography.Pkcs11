using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary><see cref="Pkcs11Key.TryEncrypt"/> and <see cref="Pkcs11Key.TryDecrypt"/> over the in-process <c>ManagedSoftToken</c>, the backend that always runs.</summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TryEncryptDecryptTests_Managed
{
    [Fact]
    public void Gcm_RoundTrips_IntoExactDestinations() => WithAesKey(TryEncryptDecryptTestCases.Assert_Gcm_RoundTrips_IntoExactDestinations);

    [Fact]
    public void TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => WithAesKey(TryEncryptDecryptTestCases.Assert_TryDecrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact]
    public void TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing() => WithAesKey(TryEncryptDecryptTestCases.Assert_TryEncrypt_DestinationTooShort_ReturnsFalse_AndLeavesNothing);

    [Fact]
    public void Gcm_IntoLargerDestinations_WritesTheResultLength() => WithAesKey(TryEncryptDecryptTestCases.Assert_Gcm_IntoLargerDestinations_WritesTheResultLength);

    [Fact]
    public void OverlappingDestination_Throws() => WithAesKey(TryEncryptDecryptTestCases.Assert_OverlappingDestination_Throws);

    private static void WithAesKey(Action<Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("try").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        body(key);
    }
}
