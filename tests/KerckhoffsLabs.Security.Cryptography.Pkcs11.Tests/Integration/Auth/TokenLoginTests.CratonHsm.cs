using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over Craton HSM — thin wrapper over <see cref="TokenLoginTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class TokenLoginTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    // See CratonHsmBackendFixture.CratonHsmTakesAContextSpecificLogin.
    // Craton accepts CKA_ALWAYS_AUTHENTICATE but does not enforce it, so such a key signs with no context PIN:
    // https://github.com/craton-co/craton-hsm-core/issues/99
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.ContextLoginAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM: C_Login refuses CKU_CONTEXT_SPECIFIC with CKR_USER_TYPE_INVALID")]
    public void AlwaysAuthenticateKey_SignsWithContextLogin() =>
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend);
}
