using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11Library.OpenWorkspaceWithoutLogin"/>: a workspace over a
/// login-not-required token (e.g. NSS softoken's public crypto services) must open a session and
/// NOT call <c>C_Login</c> — a login there fails with <see cref="CKR.CKR_USER_TYPE_INVALID"/>.
/// </summary>
public sealed class OpenWorkspaceWithoutLoginTests
{
    private const string TokenLabel = "no-login-token";

    private sealed class SlotFake : NotSupportedPkcs11Library
    {
        public int LoginCalls { get; private set; }
        public int OpenSessionCalls { get; private set; }

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
        {
            if (slotList is null) { count = (NativeCULong)1; return CKR.CKR_OK; }
            slotList[0] = (NativeCULong)7;
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        public override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        {
            NativeTestStructs.FillPadded(info.Label, TokenLabel);
            return CKR.CKR_OK;
        }

        public override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            OpenSessionCalls++;
            session = (NativeCULong)42;
            return CKR.CKR_OK;
        }

        // A no-login token rejects C_Login; record any call so the test can prove it never happens.
        public override CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen)
        {
            LoginCalls++;
            return CKR.CKR_USER_TYPE_INVALID;
        }

        public override CKR C_Logout(NativeCULong session) => CKR.CKR_USER_NOT_LOGGED_IN;
        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
    }

    [Fact]
    public void OpensSessionAndSkipsLogin()
    {
        var fake = new SlotFake();
        using var lib = new Pkcs11Library(fake);

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
        var fake = new SlotFake();
        using var lib = new Pkcs11Library(fake);
        using var pin = new SecurePin([1, 2, 3, 4]);

        // The token rejects login (CKR_USER_TYPE_INVALID), which is exactly why the no-login path
        // exists — but it proves the login overload does attempt C_Login where this one does not.
        Assert.ThrowsAny<Pkcs11Exception>(() => lib.OpenWorkspace(TokenLabel, CKU.CKU_USER, pin));
        Assert.Equal(1, fake.LoginCalls);
    }

    [Fact]
    public void UnknownLabel_Throws()
    {
        var fake = new SlotFake();
        using var lib = new Pkcs11Library(fake);

        Assert.Throws<ArgumentException>(() => lib.OpenWorkspaceWithoutLogin("no-such-token"));
    }
}
