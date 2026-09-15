using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Coverage for the protected-authentication-path overloads (BACKLOG BL-112): PKCS#11 signals
/// "collect the PIN on the token's own pinpad" by passing <c>pPin = NULL_PTR</c>, and the interop
/// layer already turns an empty span into a null pointer via <c>fixed</c> — what was missing was any
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

    // === Pkcs11Session (internal) ===========================================

    [Fact]
    public void SessionLogin_NoPin_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        var session = slot.OpenSession();
        try
        {
            AssertArgumentsBad(() => session.Login(CKU.CKU_USER));
        }
        finally
        {
            session.Dispose();
        }
    }

    [Fact]
    public void SessionSetPin_NoArgs_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        var session = slot.OpenSession();
        try
        {
            AssertArgumentsBad(() => session.SetPin());
        }
        finally
        {
            session.Dispose();
        }
    }

    [Fact]
    public void SessionInitPin_NoArg_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        var session = slot.OpenSession();
        try
        {
            // C_InitPIN requires an SO-authenticated session before it even looks at the PIN
            // pointer, so log in with a real PIN first — only InitPin itself is under test.
            using var soPin = new SecurePin(_backend.SoPin.Span);
            session.Login(CKU.CKU_SO, soPin);

            AssertArgumentsBad(() => session.InitPin());
        }
        finally
        {
            session.Dispose();
        }
    }

    // === Pkcs11Slot (public) =================================================

    [Fact]
    public void SlotInitToken_NoPin_ReachesNativeCallAsNull()
    {
        var slot = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);

        // pkcs11-mock returns CKR_ARGUMENTS_BAD before touching any token state, so this is safe to
        // run against the collection-shared mock instance.
        AssertArgumentsBad(() => slot.InitToken(_backend.TokenLabel));
    }

    // === Pkcs11Library / Pkcs11Workspace (public) ===========================

    [Fact]
    public void LibraryOpenWorkspace_NoPin_ReachesNativeCallAsNull()
    {
        AssertArgumentsBad(() => _backend.Library.OpenWorkspace(_backend.TokenLabel, CKU.CKU_USER));
    }

    [Fact]
    public void WorkspaceSetPin_NoArgs_ReachesNativeCallAsNull()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        AssertArgumentsBad(workspace.SetPin);
    }

    [Fact]
    public void WorkspaceInitPin_NoArgs_ReachesNativeCallAsNull()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_SO, new SecurePin(_backend.SoPin.Span));

        AssertArgumentsBad(workspace.InitPin);
    }
}
