using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over opencryptoki — thin wrapper over <see cref="TokenLoginTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class TokenLoginTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AlwaysAuthenticateKey_SignsWithContextLogin() =>
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend);
}
