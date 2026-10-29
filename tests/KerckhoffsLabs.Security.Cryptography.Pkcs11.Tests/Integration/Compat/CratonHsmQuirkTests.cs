using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per Craton HSM gap a gate on <see cref="CratonHsmBackendFixture"/> works around: each reproduces
/// it directly and asserts that it is still there. When a Craton bump brings the fix, the matching test
/// fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("CratonHsm")]
public sealed class CratonHsmQuirkTests(CratonHsmBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void LocalAttribute_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-local-{Guid.NewGuid():N}").ValueLen(32).Encrypt().OnToken(_backend.SupportsTokenObjects).Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        try
        {
            using var attributes = key.GetAttributeValue(CKA.CKA_LOCAL);

            Assert.True(attributes[0].CannotBeRead,
                "Craton HSM now returns CKA_LOCAL: set CratonHsmBackendFixture.SupportsLocalAttribute to true and " +
                "delete this test.");
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void PrivateObjectWithoutALogin_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        CKR logout = _backend.Library.LowLevelLibrary!.C_Logout((NativeCULong)session.SessionId);
        Assert.True(logout is CKR.CKR_OK or CKR.CKR_USER_NOT_LOGGED_IN, $"C_Logout returned {logout}.");

        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"quirk-private-{Guid.NewGuid():N}");
        Exception? ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel])));

        Assert.True(ex is null,
            "Craton HSM now refuses a private object with nobody logged in " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "CratonHsmBackendFixture.CratonHsmRefusesPrivateObjectsWithoutALogin to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void PrivateSessionObjectAfterLogout_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        using var pin = new SecurePin(_backend.UserPin.Span);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"quirk-logout-{Guid.NewGuid():N}");
        session.Login(CKU.CKU_USER, pin);
        ObjectHandle handle = session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel]);
        session.Logout();
        session.Login(CKU.CKU_USER, pin);
        Exception? ex;
        try { ex = Record.Exception(() => { using var read = session.GetAttributeValue(handle, [CKA.CKA_CLASS]); }); }
        finally { session.Logout(); }

        Assert.True(ex is null,
            "A private session object no longer outlives C_Logout " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "CratonHsmBackendFixture.CratonHsmDestroysPrivateSessionObjectsOnLogout to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SessionObjectInReadOnlySession_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore(readWrite: false);
        using var pin = new SecurePin(_backend.UserPin.Span);
        session.Login(CKU.CKU_USER, pin);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"quirk-ro-{Guid.NewGuid():N}");
        Exception? ex;
        try { ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrToken, attrLabel]))); }
        finally { session.Logout(); }

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_SESSION_READ_ONLY },
            "Craton HSM no longer refuses a session object in a read-only session with CKR_SESSION_READ_ONLY " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "CratonHsmBackendFixture.CratonHsmMakesSessionObjectsInReadOnlySessions to true and delete this test.");
    }
}
