using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over BouncyHsm — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SessionConformanceTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void LoginStateMachine_AnswersAsSpecified() => SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn() => SessionConformanceTestCases.Assert_WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void PrivateObjects_AreHiddenWithoutALogin() => SessionConformanceTestCases.Assert_PrivateObjects_AreHiddenWithoutALogin(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ReadOnlySession_RefusesTokenObjects() => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjects(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts()
    {
        Assert.Skip("BouncyHsm shows a session object only to the session that created it.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking() => SessionConformanceTestCases.Assert_SecondLibraryInstance_LeavesTheFirstWorking(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.PrivateObjectCreations), MemberType = typeof(SessionConformanceTestCases))]
    public void PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(string call) => SessionConformanceTestCases.Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(_backend, call);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.LogoutInvalidationAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm keeps private session objects after C_Logout")]
    public void Logout_InvalidatesPrivateHandles() => SessionConformanceTestCases.Assert_Logout_InvalidatesPrivateHandles(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.SoUserExclusionAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm logs the user in over the SO")]
    public void SoAndUser_ExcludeEachOther() => SessionConformanceTestCases.Assert_SoAndUser_ExcludeEachOther(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.SoPrivateObjectRefusalAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm lets the SO make a private object")]
    public void So_CreatesNoPrivateObject() => SessionConformanceTestCases.Assert_So_CreatesNoPrivateObject(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.ReadOnlySessionWrites), MemberType = typeof(SessionConformanceTestCases))]
    public void ReadOnlySession_RefusesTokenObjectWrites(string call) => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjectWrites(_backend, call);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.PinLengthRangeAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm reports its maximum PIN length as its minimum")]
    public void PinOutsideTheLengthRange_IsRefused() => SessionConformanceTestCases.Assert_PinOutsideTheLengthRange_IsRefused(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.ShortMechanismListAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm leaves *pulCount as given on CKR_BUFFER_TOO_SMALL")]
    public void MechanismList_OneShort_IsBufferTooSmall() => SessionConformanceTestCases.Assert_MechanismList_OneShort_IsBufferTooSmall(_backend);
}
