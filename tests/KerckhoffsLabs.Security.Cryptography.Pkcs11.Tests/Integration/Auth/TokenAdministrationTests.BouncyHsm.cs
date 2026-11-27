using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>Token administration over BouncyHsm — thin wrapper over <see cref="TokenAdministrationTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class TokenAdministrationTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void LogoutOfOneToken_LeavesTheOtherLoggedIn() =>
        TokenAdministrationTestCases.Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(_backend,
            destroysPrivateSessionObjects: BouncyHsmBackendFixture.BouncyHsmDestroysPrivateSessionObjectsOnLogout);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ReinitializedToken_KeepsNothingFromBefore() =>
        TokenAdministrationTestCases.Assert_ReinitializedToken_KeepsNothingFromBefore(_backend,
            initTokenDisablesTheUser: BouncyHsmBackendFixture.BouncyHsmDisablesTheUserOnInitToken);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ConcurrentSetPin_ThroughTheLibrary_OneWins() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.AtomicSetPinAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.AtomicSetPinAvailable))]
    public void ConcurrentSetPin_AtTheModule_Linearizes() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_AtTheModule_Linearizes(_backend);
}
