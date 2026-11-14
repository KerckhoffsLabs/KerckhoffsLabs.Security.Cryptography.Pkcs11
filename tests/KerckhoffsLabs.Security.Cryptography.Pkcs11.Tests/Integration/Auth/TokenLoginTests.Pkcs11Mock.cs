using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>The token login model over pkcs11-mock, which allows one open session: thin wrapper over the
/// <c>Assert_OneSessionToken_*</c> cases of <see cref="TokenLoginTestCases"/>.</summary>
/// <remarks>
/// A login lends its own session to <c>login.OpenSession()</c> there (<c>C_OpenSession</c> answers
/// <c>CKR_SESSION_COUNT</c> for a second session, and the login lends instead). The other cases of
/// <see cref="TokenLoginTestCases"/> are not run: four need two working sessions at once, one needs a slot session
/// beside a login, and all would skip anyway, since the mock's <c>RequiresUserLogin</c> is <see langword="false"/>.
/// The fixture keeps no login: its anchor would take the mock's only session from every other mock test. Each case
/// here disposes everything it opens, so the session is free for the next test.
/// </remarks>
[Collection("Mock")]
public sealed class TokenLoginTests_Pkcs11Mock(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    [Fact]
    public void OneSessionToken_LoginLendsItsSession() =>
        TokenLoginTestCases.Assert_OneSessionToken_LoginLendsItsSession(_backend);

    [Fact]
    public void OneSessionToken_SecondSessionRefused_WhileLent() =>
        TokenLoginTestCases.Assert_OneSessionToken_SecondSessionRefused_WhileLent(_backend);

    [Fact]
    public void OneSessionToken_DisposedSessionIsLentAgain() =>
        TokenLoginTestCases.Assert_OneSessionToken_DisposedSessionIsLentAgain(_backend);

    [Fact]
    public void OneSessionToken_LastHolderFreesTheToken() =>
        TokenLoginTestCases.Assert_OneSessionToken_LastHolderFreesTheToken(_backend);

    [Fact]
    public void OneSessionToken_SlotSessionRefusedWhileLoggedIn() =>
        TokenLoginTestCases.Assert_OneSessionToken_SlotSessionRefusedWhileLoggedIn(_backend);

    [Fact]
    public void OneSessionToken_LoginRefusedWhileSlotSessionOpen() =>
        TokenLoginTestCases.Assert_OneSessionToken_LoginRefusedWhileSlotSessionOpen(_backend);
}
