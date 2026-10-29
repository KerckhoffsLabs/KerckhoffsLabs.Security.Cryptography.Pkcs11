using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>SessionConformance over Kryoptic — thin wrapper over <see cref="SessionConformanceTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SessionConformanceTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SlotAndTokenInfo_AreConsistent() => SessionConformanceTestCases.Assert_SlotAndTokenInfo_AreConsistent(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MechanismList_IsConsistent() => SessionConformanceTestCases.Assert_MechanismList_IsConsistent(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SessionStates_FollowTheTokensLogin() => SessionConformanceTestCases.Assert_SessionStates_FollowTheTokensLogin(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void LoginStateMachine_AnswersAsSpecified() => SessionConformanceTestCases.Assert_LoginStateMachine_AnswersAsSpecified(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn() => SessionConformanceTestCases.Assert_WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void PrivateObjects_AreHiddenWithoutALogin() => SessionConformanceTestCases.Assert_PrivateObjects_AreHiddenWithoutALogin(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ReadOnlySession_RefusesTokenObjects() => SessionConformanceTestCases.Assert_ReadOnlySession_RefusesTokenObjects(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaleHandles_AreRefused() => SessionConformanceTestCases.Assert_StaleHandles_AreRefused(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SessionObject_OutlivesNoSessionOfIts() => SessionConformanceTestCases.Assert_SessionObject_OutlivesNoSessionOfIts(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SecondLibraryInstance_LeavesTheFirstWorking() => SessionConformanceTestCases.Assert_SecondLibraryInstance_LeavesTheFirstWorking(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.PrivateObjectLoginCheckAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Kryoptic makes a private session object with nobody logged in")]
    [MemberData(nameof(SessionConformanceTestCases.PrivateObjectCreations), MemberType = typeof(SessionConformanceTestCases))]
    public void PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(string call) => SessionConformanceTestCases.Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(_backend, call);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Logout_InvalidatesPrivateHandles()
    {
        // Kryoptic answers C_EncryptInit with a private token key after C_Logout with CKR_GENERAL_ERROR.
        SessionConformanceTestCases.Assert_Logout_InvalidatesPrivateHandles(_backend,
            tokenKeyEncryptInit: KryopticBackendFixture.KryopticRefusesAPrivateKeyAfterLogout ? null : CKR.CKR_GENERAL_ERROR);
    }
}
