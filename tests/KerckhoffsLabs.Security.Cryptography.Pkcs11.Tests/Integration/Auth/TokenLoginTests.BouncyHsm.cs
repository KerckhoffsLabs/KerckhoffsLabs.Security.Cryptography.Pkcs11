using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Xunit.Sdk;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over BouncyHsm — thin wrapper over <see cref="TokenLoginTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class TokenLoginTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    // On the qualified-area token, which marks the key itself: see BouncyHsmBackendFixture.BouncyHsmTakesAlwaysAuthenticateInATemplate.
    // The template quirk is reported upstream: https://github.com/harrison314/BouncyHsm/issues/145
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AlwaysAuthenticateKey_SignsWithContextLogin()
    {
        BouncyHsmQualifiedAreaToken token = _backend.QualifiedAreaToken
            ?? throw SkipException.ForSkip(_backend.QualifiedAreaUnavailableReason ?? "BouncyHsm's qualified-area token is not set up.");
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(token, tokenMarksTheKey: true,
            contextPin: token.SignaturePin);
    }
}
