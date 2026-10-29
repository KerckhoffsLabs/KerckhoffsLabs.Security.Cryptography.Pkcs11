using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over opencryptoki — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SessionConformanceTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void LoginStateMachine_AnswersAsSpecified() => SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn() => SessionConformanceTestCases.Assert_WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void PrivateObjects_AreHiddenWithoutALogin() => SessionConformanceTestCases.Assert_PrivateObjects_AreHiddenWithoutALogin(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ReadOnlySession_RefusesTokenObjects() => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjects(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts() => SessionConformanceTestCases.Assert_SessionObject_OutlivesNoSessionOfIts(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking() => SessionConformanceTestCases.Assert_SecondLibraryInstance_LeavesTheFirstWorking(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.PrivateObjectCreations), MemberType = typeof(SessionConformanceTestCases))]
    public void PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(string call) => SessionConformanceTestCases.Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(_backend, call);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Logout_InvalidatesPrivateHandles() => SessionConformanceTestCases.Assert_Logout_InvalidatesPrivateHandles(_backend);
}
