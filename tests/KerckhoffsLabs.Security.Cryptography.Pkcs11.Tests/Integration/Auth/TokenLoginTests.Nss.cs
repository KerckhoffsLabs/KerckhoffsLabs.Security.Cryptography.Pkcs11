using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over NSS softoken — thin wrapper over <see cref="TokenLoginTestCases"/>.</summary>
/// <remarks>Its token has no login (<see cref="NssBackendFixture.RequiresUserLogin"/>), so the login cases skip; it is
/// the write-protected token the read-only case needs.</remarks>
[Collection("Nss")]
public sealed class TokenLoginTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AlwaysAuthenticateKey_SignsWithContextLogin() =>
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void WriteProtectedToken_OpensReadOnly() =>
        TokenLoginTestCases.Assert_WriteProtectedToken_OpensReadOnly(_backend);
}
