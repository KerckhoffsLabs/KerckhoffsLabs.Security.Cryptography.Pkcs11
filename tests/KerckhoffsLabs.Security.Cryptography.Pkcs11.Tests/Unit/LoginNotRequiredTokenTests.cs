using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// A login-not-required token (e.g. NSS softoken's public crypto services) is used through
/// <see cref="Pkcs11Slot.OpenSession"/>, which opens a session and does NOT call <c>C_Login</c>: a login there
/// fails with <see cref="CKR.CKR_USER_TYPE_INVALID"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LoginNotRequiredTokenTests
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

        using (var session = lib.GetSlotByTokenLabel(TokenLabel).OpenSession(SessionAccess.ReadWrite))
        {
            Assert.Equal(TokenLabel, session.Slot.GetTokenInfo().Label);
        }

        Assert.Equal(1, fake.OpenSessionCalls);
        Assert.Equal(0, fake.LoginCalls); // never logged in
    }

    [Fact]
    public void Login_DoesCallLogin_ForContrast()
    {
        using var fake = new SlotFake();
        using var lib = fake.Load();
        using var pin = new SecurePin([1, 2, 3, 4]);

        // The token rejects login (CKR_USER_TYPE_INVALID), which is exactly why the no-login path
        // exists — but it proves a login does attempt C_Login where a slot's session does not.
        Assert.ThrowsAny<Pkcs11Exception>(() => lib.GetSlotByTokenLabel(TokenLabel).Login(TokenUser.User, pin));
        Assert.Equal(1, fake.LoginCalls);
    }
}
