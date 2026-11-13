using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Coverage for the protected-authentication-path overloads: PKCS#11 signals
/// "collect the PIN on the token's own pinpad" by passing <c>pPin = NULL_PTR</c>, and the interop
/// layer already turns an empty span into a null pointer via <see langword="fixed"/> — what was missing was any
/// public entry point that could produce an empty span at all, since every one required a non-empty
/// <see cref="SecurePin"/>. pkcs11-mock does not advertise
/// <see cref="TokenFlags.ProtectedAuthenticationPath"/> and its <c>C_Login</c>/<c>C_InitPIN</c>/
/// <c>C_SetPIN</c>/<c>C_InitToken</c> all reject a null PIN pointer with
/// <see cref="CKR.CKR_ARGUMENTS_BAD"/> (verified against vendor/pkcs11-mock/src/pkcs11-mock.c) — so
/// getting exactly that return code back, rather than a managed-side guard throwing first, is direct
/// proof the empty span reached the native call as NULL.
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
    public void SessionSetPin_NoArgs_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        AssertArgumentsBad(() => session.SetPin());
    }

    [Fact]
    public void SessionInitPin_NoArg_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        // C_InitPIN requires an SO-authenticated session before it even looks at the PIN
        // pointer, so log in with a real PIN first — only InitPin itself is under test.
        using var soPin = new SecurePin(_backend.SoPin.Span);
        session.SendLogin(CKU.CKU_SO, soPin.Pin);

        AssertArgumentsBad(() => session.InitPin());
    }

    // === Pkcs11Slot (public) =================================================

    [Fact]
    public void SlotInitTokenWithPinpad_NoPin_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);

        // pkcs11-mock returns CKR_ARGUMENTS_BAD before touching any token state, so this is safe to
        // run against the collection-shared mock instance.
        AssertArgumentsBad(() => slot.InitTokenWithPinpad(_backend.TokenLabel));
    }

    // === Pkcs11Slot / Pkcs11Session (public) ==============================

    // The login's own session is the mock's only one; it is closed again when the module refuses the login.
    [Fact]
    public void SlotLoginWithPinpad_NoPin_ReachesNativeCallAsNull() =>
        AssertArgumentsBad(() => _backend.Slot.LoginWithPinpad(TokenUser.User));

    [Fact]
    public void SessionSetPinWithPinpad_NoArgs_ReachesNativeCallAsNull()
    {
        using var session = _backend.OpenSession();

        AssertArgumentsBad(session.SetPinWithPinpad);
    }

    [Fact]
    public void SessionInitPinWithPinpad_NoArgs_ReachesNativeCallAsNull()
    {
        // pkcs11-mock allows one session, so an SO login (which keeps a session of its own) cannot open a second one
        // to work on: the SO logs in on the session itself, through the internal core. Closing the session ends
        // the mock's login.
        Pkcs11Slot slot = _backend.Slot;
        using var session = new Pkcs11Session(_backend.Library, slot, slot.OpenSessionCore());
        using (var soPin = new SecurePin(_backend.SoPin.Span))
            session.Core.SendLogin(CKU.CKU_SO, soPin.Pin);

        AssertArgumentsBad(session.InitPinWithPinpad);
    }
}
