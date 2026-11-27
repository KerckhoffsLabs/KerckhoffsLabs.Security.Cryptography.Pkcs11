using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>Token administration over FreeHSM — thin wrapper over <see cref="TokenAdministrationTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class TokenAdministrationTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void LogoutOfOneToken_LeavesTheOtherLoggedIn() =>
        TokenAdministrationTestCases.Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ReinitializedToken_KeepsNothingFromBefore() =>
        TokenAdministrationTestCases.Assert_ReinitializedToken_KeepsNothingFromBefore(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ConcurrentSetPin_ThroughTheLibrary_OneWins() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.AtomicSetPinAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.AtomicSetPinAvailable))]
    public void ConcurrentSetPin_AtTheModule_Linearizes() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_AtTheModule_Linearizes(_backend);
}
