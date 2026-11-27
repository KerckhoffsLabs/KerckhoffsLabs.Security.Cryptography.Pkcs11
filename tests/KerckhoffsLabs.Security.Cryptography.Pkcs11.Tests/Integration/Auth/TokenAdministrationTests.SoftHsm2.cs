using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>Token administration over SoftHSM2 — thin wrapper over <see cref="TokenAdministrationTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class TokenAdministrationTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void LogoutOfOneToken_LeavesTheOtherLoggedIn() =>
        TokenAdministrationTestCases.Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ReinitializedToken_KeepsNothingFromBefore() =>
        TokenAdministrationTestCases.Assert_ReinitializedToken_KeepsNothingFromBefore(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ConcurrentSetPin_ThroughTheLibrary_OneWins() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ConcurrentSetPin_AtTheModule_Linearizes() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_AtTheModule_Linearizes(_backend);
}
