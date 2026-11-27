using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>Token administration over Craton HSM — thin wrapper over <see cref="TokenAdministrationTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class TokenAdministrationTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void LogoutOfOneToken_LeavesTheOtherLoggedIn() =>
        TokenAdministrationTestCases.Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(_backend,
            destroysPrivateSessionObjects: CratonHsmBackendFixture.CratonHsmDestroysPrivateSessionObjectsOnLogout);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ReinitializedToken_KeepsNothingFromBefore() =>
        TokenAdministrationTestCases.Assert_ReinitializedToken_KeepsNothingFromBefore(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ConcurrentSetPin_ThroughTheLibrary_OneWins() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ConcurrentSetPin_AtTheModule_Linearizes() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_AtTheModule_Linearizes(_backend);
}
