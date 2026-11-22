using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.Cnsa20"/> over Kryoptic — thin wrapper over <see cref="Cnsa20PolicyTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class Cnsa20PolicyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Aes256Gcm_RoundTrips() =>
        Cnsa20PolicyTestCases.Assert_Aes256Gcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Aes128_IsRefused_AtGeneration_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_Aes128_IsRefused_AtGeneration_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Aes128FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_Aes128FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesKw_UnwrapsAes256() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapsAes256(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MlKem1024_EncapsulatesAndDecapsulates() =>
        Cnsa20PolicyTestCases.Assert_MlKem1024_EncapsulatesAndDecapsulates(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MlKem768_IsRefused_AtGeneration() =>
        Cnsa20PolicyTestCases.Assert_MlKem768_IsRefused_AtGeneration(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MlDsa87_SignsAndVerifies() =>
        Cnsa20PolicyTestCases.Assert_MlDsa87_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MlDsa65FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_MlDsa65FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RsaPss_IsRefused_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_RsaPss_IsRefused_BeforeTheToken(_backend);
}
