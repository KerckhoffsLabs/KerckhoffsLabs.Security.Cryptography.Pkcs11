using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over FreeHSM — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class SessionConformanceTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void LoginStateMachine_AnswersAsSpecified() => SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend);

    // No wrong-PIN case: right after a wrong PIN, FreeHSM refuses the right one with a vendor code
    // (0x80000004), which would lock the rest of the collection out of the token.

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ReadOnlySession_RefusesTokenObjects() => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjects(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts() => SessionConformanceTestCases.Assert_SessionObject_OutlivesNoSessionOfIts(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking()
    {
        Assert.Skip("FreeHSM refuses a second C_Initialize in one process with CKR_FUNCTION_FAILED, not CKR_CRYPTOKI_ALREADY_INITIALIZED.");
    }
}
