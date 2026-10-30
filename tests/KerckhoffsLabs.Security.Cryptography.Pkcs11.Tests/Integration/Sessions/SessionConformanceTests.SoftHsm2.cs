using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over SoftHSM2 — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class SessionConformanceTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void LoginStateMachine_AnswersAsSpecified()
    {
        // SoftHSM2 answers C_Logout with CKR_OK when nobody is logged in.
        SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend, logoutWithNobodyLoggedIn: CKR.CKR_OK);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn() => SessionConformanceTestCases.Assert_WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void PrivateObjects_AreHiddenWithoutALogin() => SessionConformanceTestCases.Assert_PrivateObjects_AreHiddenWithoutALogin(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ReadOnlySession_RefusesTokenObjects() => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjects(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts() => SessionConformanceTestCases.Assert_SessionObject_OutlivesNoSessionOfIts(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking() => SessionConformanceTestCases.Assert_SecondLibraryInstance_LeavesTheFirstWorking(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.PrivateObjectCreations), MemberType = typeof(SessionConformanceTestCases))]
    public void PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(string call) => SessionConformanceTestCases.Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(_backend, call);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Logout_InvalidatesPrivateHandles() => SessionConformanceTestCases.Assert_Logout_InvalidatesPrivateHandles(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SoAndUser_ExcludeEachOther() => SessionConformanceTestCases.Assert_SoAndUser_ExcludeEachOther(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void So_CreatesNoPrivateObject() => SessionConformanceTestCases.Assert_So_CreatesNoPrivateObject(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.ReadOnlySessionWrites), MemberType = typeof(SessionConformanceTestCases))]
    public void ReadOnlySession_RefusesTokenObjectWrites(string call) => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjectWrites(_backend, call);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void PinOutsideTheLengthRange_IsRefused() => SessionConformanceTestCases.Assert_PinOutsideTheLengthRange_IsRefused(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void MechanismList_OneShort_IsBufferTooSmall() => SessionConformanceTestCases.Assert_MechanismList_OneShort_IsBufferTooSmall(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaMechanisms_AdvertiseThe2048BitKeysTheyTake() => SessionConformanceTestCases.Assert_RsaMechanisms_AdvertiseThe2048BitKeysTheyTake(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ClockOnToken_ReportsAWellFormedUtcTime() => SessionConformanceTestCases.Assert_ClockOnToken_ReportsAWellFormedUtcTime(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(SessionConformanceTestCases.AdvertisedKeyWraps), MemberType = typeof(SessionConformanceTestCases))]
    public void AdvertisedWrapMechanism_WrapsAnAesKey(CKM mechanism)
    {
        if (SoftHsmBackendFixture.IsV240Leg && mechanism == CKM.CKM_RSA_PKCS_OAEP)
            Assert.Skip("SoftHSM 2.5 takes only SHA-1 as the OAEP hash, and refuses SHA-256 with CKR_ARGUMENTS_BAD.");
        SessionConformanceTestCases.Assert_AdvertisedWrapMechanism_WrapsAnAesKey(_backend, mechanism);
    }
}
