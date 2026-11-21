using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Coverage for the protected-authentication-path overloads against a token without a pinpad. PKCS#11 signals "collect
/// the PIN on the token's own pinpad" by passing <c>pPin = NULL_PTR</c>, and gives that a meaning only on a token with
/// <see cref="TokenFlags.ProtectedAuthenticationPath"/>. pkcs11-mock does not advertise it, and its
/// <c>C_Login</c>/<c>C_InitPIN</c>/<c>C_SetPIN</c>/<c>C_InitToken</c> reject a null PIN pointer with
/// <see cref="CKR.CKR_ARGUMENTS_BAD"/> (vendor/pkcs11-mock/src/pkcs11-mock.c). The internal send, which has no check of
/// its own, gets exactly that code back: direct proof the empty span reaches the native call as NULL. Every public
/// pinpad call, and the record's internal sends, are refused before the module instead, with nothing sent.
/// </summary>
[Collection("Mock")]
public sealed class ProtectedAuthenticationPathTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private static void AssertArgumentsBad(Action action)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(action);
        Assert.Equal(CKR.CKR_ARGUMENTS_BAD, ex.ReturnValue);
    }

    // The library's refusal of a pinpad call on a token without one: an InvalidOperationException, before the module.
    private static void AssertRefusedNoPinpad(Action action)
    {
        var ex = Assert.Throws<InvalidOperationException>(action);
        Assert.Contains("no protected authentication path", ex.Message, StringComparison.Ordinal);
    }

    // === Pkcs11SessionCore (internal) ===========================================

    [Fact]
    public void SessionLogin_NoPin_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        AssertArgumentsBad(() => session.SendLogin(CKU.CKU_USER, default));
    }

    [Fact]
    public void SessionSetPin_NoArgs_NoPinpad_RefusedBeforeTheModule()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        AssertRefusedNoPinpad(() => session.SetPin());
    }

    [Fact]
    public void SessionInitPin_NoArg_NoPinpad_RefusedBeforeTheModule()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        // C_InitPIN requires an SO-authenticated session before it even looks at the PIN
        // pointer, so log in with a real PIN first — only InitPin itself is under test. This is the send
        // Pkcs11Login.InitUserPinWithPinpad makes on the SO login's anchor; that public path is
        // LoginInitUserPinWithPinpad_NoPinpad_RefusedBeforeTheModule below.
        using var soPin = new SecurePin(_backend.SoPin.Span);
        session.SendLogin(CKU.CKU_SO, soPin.Pin);

        AssertRefusedNoPinpad(() => session.SendInitPin(default));
    }

    // === Pkcs11Slot (public) =================================================

    [Fact]
    public void SlotInitTokenWithPinpad_NoPinpad_RefusedBeforeTheModule()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);

        // Refused before C_InitToken: the collection-shared mock token is untouched.
        AssertRefusedNoPinpad(() => slot.InitTokenWithPinpad(_backend.TokenLabel));
    }

    // === Pkcs11Slot / Pkcs11Session (public) ==============================

    // The login's own session is closed again when the login is refused.
    [Fact]
    public void SlotLoginWithPinpad_NoPinpad_RefusedBeforeTheModule() =>
        AssertRefusedNoPinpad(() => _backend.Slot.Login(TokenUser.User, LoginCredential.Pinpad));

    [Fact]
    public void SessionSetPinWithPinpad_NoPinpad_RefusedBeforeTheModule()
    {
        using var session = _backend.OpenSession();

        AssertRefusedNoPinpad(session.SetPinWithPinpad);
    }

    // The SO login made with its PIN; only C_InitPIN on the pinpad is refused.
    [Fact]
    public void LoginInitUserPinWithPinpad_NoPinpad_RefusedBeforeTheModule()
    {
        using var soPin = new SecurePin(_backend.SoPin.Span);
        using Pkcs11Login login = _backend.Slot.Login(TokenUser.SecurityOfficer, soPin);

        AssertRefusedNoPinpad(login.InitUserPinWithPinpad);
    }
}
