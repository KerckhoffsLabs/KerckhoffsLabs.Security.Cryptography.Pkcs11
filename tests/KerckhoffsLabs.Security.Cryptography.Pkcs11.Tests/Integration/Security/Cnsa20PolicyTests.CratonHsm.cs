using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.Cnsa20"/> over Craton HSM — thin wrapper over <see cref="Cnsa20PolicyTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class Cnsa20PolicyTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Aes256Gcm_RoundTrips() =>
        Cnsa20PolicyTestCases.Assert_Aes256Gcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Aes128_IsRefused_AtGeneration_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_Aes128_IsRefused_AtGeneration_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Aes128FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_Aes128FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void AesKw_UnwrapsAes256() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapsAes256(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MlKem1024_EncapsulatesAndDecapsulates() =>
        Cnsa20PolicyTestCases.Assert_MlKem1024_EncapsulatesAndDecapsulates(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MlKem768_IsRefused_AtGeneration() =>
        Cnsa20PolicyTestCases.Assert_MlKem768_IsRefused_AtGeneration(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MlDsa87_SignsAndVerifies() =>
        Cnsa20PolicyTestCases.Assert_MlDsa87_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MlDsa65FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_MlDsa65FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void RsaPss_IsRefused_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_RsaPss_IsRefused_BeforeTheToken(_backend);
}
