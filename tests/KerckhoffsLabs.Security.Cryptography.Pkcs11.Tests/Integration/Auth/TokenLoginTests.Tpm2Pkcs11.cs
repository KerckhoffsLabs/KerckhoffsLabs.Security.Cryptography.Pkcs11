using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over tpm2-pkcs11 — thin wrapper over <see cref="TokenLoginTestCases"/>.</summary>
/// <remarks>tpm2-pkcs11 makes key pairs on the token only (tpm2-software/tpm2-pkcs11#921, see
/// <see cref="Tpm2Pkcs11BackendFixture.Tpm2Pkcs11MakesSessionKeyPairs"/>), so the signing keys are token objects,
/// destroyed by each case.</remarks>
[Collection("Tpm2Pkcs11")]
public sealed class TokenLoginTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    // The signing keys are sign-only key pairs: see Tpm2Pkcs11BackendFixture.Tpm2Pkcs11AcceptsSignOnlyKeyPairs.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void TwoSessionsUnderOneLogin_BothSignWithAPrivateKey() =>
        TokenLoginTestCases.Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(_backend, tokenKeys: true);

    // The signing keys are sign-only key pairs: see Tpm2Pkcs11BackendFixture.Tpm2Pkcs11AcceptsSignOnlyKeyPairs.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void DisposingOneSession_OtherKeepsSigning() =>
        TokenLoginTestCases.Assert_DisposingOneSession_OtherKeepsSigning(_backend, tokenKeys: true);

    // The signing keys are sign-only key pairs: see Tpm2Pkcs11BackendFixture.Tpm2Pkcs11AcceptsSignOnlyKeyPairs.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void DisposingTheLogin_SessionsKeepWorkingUntilLastCloses() =>
        TokenLoginTestCases.Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(_backend, tokenKeys: true);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void AfterLastHolder_SlotSessionIsPublic() =>
        TokenLoginTestCases.Assert_AfterLastHolder_SlotSessionIsPublic(_backend);

    // The signing keys are sign-only key pairs: see Tpm2Pkcs11BackendFixture.Tpm2Pkcs11AcceptsSignOnlyKeyPairs.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void AlwaysAuthenticateKey_SignsWithContextLogin() =>
        TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend, tokenKeys: true);
}
