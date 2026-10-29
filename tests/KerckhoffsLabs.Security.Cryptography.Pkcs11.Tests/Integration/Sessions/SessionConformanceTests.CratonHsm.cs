using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over Craton HSM — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class SessionConformanceTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void LoginStateMachine_AnswersAsSpecified() => SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend);

    // No wrong-PIN case: Craton HSM rate-limits logins after a wrong PIN, which would lock the rest of the
    // collection out of the token.

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void PrivateObjects_AreHiddenWithoutALogin() => SessionConformanceTestCases.Assert_PrivateObjects_AreHiddenWithoutALogin(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ReadOnlySession_RefusesTokenObjects()
    {
        Assert.Skip("Craton HSM refuses a session object in a read-only session too, with CKR_SESSION_READ_ONLY.");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts()
    {
        Assert.Skip("Craton HSM keeps a session object after the session that created it closes.");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking() => SessionConformanceTestCases.Assert_SecondLibraryInstance_LeavesTheFirstWorking(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.PrivateObjectLoginCheckAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM makes a private object with nobody logged in")]
    [MemberData(nameof(SessionConformanceTestCases.PrivateObjectCreations), MemberType = typeof(SessionConformanceTestCases))]
    public void PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(string call) => SessionConformanceTestCases.Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(_backend, call);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.LogoutInvalidationAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM keeps private session objects after C_Logout")]
    public void Logout_InvalidatesPrivateHandles() => SessionConformanceTestCases.Assert_Logout_InvalidatesPrivateHandles(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SoAndUser_ExcludeEachOther() => SessionConformanceTestCases.Assert_SoAndUser_ExcludeEachOther(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.PrivateObjectLoginCheckAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM lets the SO make a private object")]
    public void So_CreatesNoPrivateObject() => SessionConformanceTestCases.Assert_So_CreatesNoPrivateObject(_backend);
}
