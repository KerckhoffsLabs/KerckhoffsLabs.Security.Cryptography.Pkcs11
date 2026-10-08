using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11Library.OpenWorkspaceWithoutLogin"/>: a workspace over a
/// login-not-required token (e.g. NSS softoken's public crypto services) must open a session and
/// NOT call <c>C_Login</c> — a login there fails with <see cref="CKR.CKR_USER_TYPE_INVALID"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class OpenWorkspaceWithoutLoginTests
{
    private const string TokenLabel = "no-login-token";

    private sealed class SlotFake : FakeModule
    {
        public int LoginCalls { get; private set; }
        public int OpenSessionCalls { get; private set; }

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            if (slotList.IsNull) { count = (NativeCULong)1; return CKR.CKR_OK; }
            slotList.Span[0] = (NativeCULong)7;
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        {
            NativeTestStructs.FillPadded(info.Label, TokenLabel);
            return CKR.CKR_OK;
        }

        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            OpenSessionCalls++;
            session = (NativeCULong)42;
            return CKR.CKR_OK;
        }

        // A no-login token rejects C_Login; record any call so the test can prove it never happens.
        protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
        {
            LoginCalls++;
            return CKR.CKR_USER_TYPE_INVALID;
        }

        protected override CKR C_Logout(NativeCULong session) => CKR.CKR_USER_NOT_LOGGED_IN;
        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
    }

    [Fact]
    public void OpensSessionAndSkipsLogin()
    {
        using var fake = new SlotFake();
        using var lib = fake.Load();

        using (var workspace = lib.OpenWorkspaceWithoutLogin(TokenLabel))
        {
            Assert.Equal(TokenLabel, workspace.Slot.GetTokenInfo().Label);
        }

        Assert.Equal(1, fake.OpenSessionCalls);
        Assert.Equal(0, fake.LoginCalls); // never logged in
    }

    [Fact]
    public void LoginOverload_DoesCallLogin_ForContrast()
    {
        using var fake = new SlotFake();
        using var lib = fake.Load();
        using var pin = new SecurePin([1, 2, 3, 4]);

        // The token rejects login (CKR_USER_TYPE_INVALID), which is exactly why the no-login path
        // exists — but it proves the login overload does attempt C_Login where this one does not.
        Assert.ThrowsAny<Pkcs11Exception>(() => lib.OpenWorkspaceWithPin(TokenLabel, CKU.CKU_USER, pin));
        Assert.Equal(1, fake.LoginCalls);
    }

    [Fact]
    public void UnknownLabel_Throws()
    {
        using var fake = new SlotFake();
        using var lib = fake.Load();

        Assert.Throws<ArgumentException>(() => lib.OpenWorkspaceWithoutLogin("no-such-token"));
    }
}
