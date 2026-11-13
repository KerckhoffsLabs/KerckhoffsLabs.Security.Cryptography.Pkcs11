using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over pkcs11-mock — thin wrapper over <see cref="TokenLoginTestCases"/>, none of whose
/// cases runs here.</summary>
/// <remarks>pkcs11-mock allows one open session at a time (<c>C_OpenSession</c> answers <c>CKR_SESSION_COUNT</c> for a
/// second; see <see cref="MockBackendFixture.MockAllowsSeveralSessions"/>). A login keeps a session of its own besides the
/// ones it opens, so its first working session is refused there. The login model is tested over fakes
/// (<c>LoginTokenModule</c>) and on the backends that allow several sessions.</remarks>
[Collection("Mock")]
public sealed class TokenLoginTests_Pkcs11Mock(MockBackendFixture backend)
{
    private const string OneSession = "pkcs11-mock allows one open session; a login needs its own session besides the one a case works on (CKR_SESSION_COUNT)";

    private readonly MockBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(MockBackendFixture.LoginSessionsAvailable), SkipType = typeof(MockBackendFixture), Skip = OneSession)]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend);

    [Fact(SkipUnless = nameof(MockBackendFixture.LoginSessionsAvailable), SkipType = typeof(MockBackendFixture), Skip = OneSession)]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend);

    [Fact(SkipUnless = nameof(MockBackendFixture.LoginSessionsAvailable), SkipType = typeof(MockBackendFixture), Skip = OneSession)]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend);

    [Fact(SkipUnless = nameof(MockBackendFixture.LoginSessionsAvailable), SkipType = typeof(MockBackendFixture), Skip = OneSession)]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    [Fact(SkipUnless = nameof(MockBackendFixture.LoginSessionsAvailable), SkipType = typeof(MockBackendFixture), Skip = OneSession)]
    public void AlwaysAuthenticateKey_SignsWithContextLogin() =>
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend);
}
