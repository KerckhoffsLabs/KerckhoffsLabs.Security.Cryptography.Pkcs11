using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.Cnsa20"/> over NSS softoken — thin wrapper over <see cref="Cnsa20PolicyTestCases"/>.</summary>
[Collection("Nss")]
public sealed class Cnsa20PolicyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Aes256Gcm_RoundTrips() =>
        Cnsa20PolicyTestCases.Assert_Aes256Gcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Aes128_IsRefused_AtGeneration_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_Aes128_IsRefused_AtGeneration_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Aes128FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_Aes128FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesKw_UnwrapsAes256() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapsAes256(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey() =>
        Cnsa20PolicyTestCases.Assert_AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void MlKem1024_EncapsulatesAndDecapsulates() =>
        Cnsa20PolicyTestCases.Assert_MlKem1024_EncapsulatesAndDecapsulates(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void MlKem768_IsRefused_AtGeneration() =>
        Cnsa20PolicyTestCases.Assert_MlKem768_IsRefused_AtGeneration(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void MlDsa87_SignsAndVerifies() =>
        Cnsa20PolicyTestCases.Assert_MlDsa87_SignsAndVerifies(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void MlDsa65FromAnotherPolicy_IsRefused_AtUse() =>
        Cnsa20PolicyTestCases.Assert_MlDsa65FromAnotherPolicy_IsRefused_AtUse(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPss_IsRefused_BeforeTheToken() =>
        Cnsa20PolicyTestCases.Assert_RsaPss_IsRefused_BeforeTheToken(_backend);
}
