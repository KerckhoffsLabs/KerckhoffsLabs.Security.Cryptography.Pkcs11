using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// No <c>CK_NOTIFY</c> callback is ever registered: a callback the module may call after the call
/// returns needs an owner keeping it alive, and nothing here is one. The module sees NULL for both
/// <c>pApplication</c> and <c>Notify</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class OpenSessionCallbackTests
{
    [Fact]
    public void OpenSession_PassesNullApplicationAndNotify()
    {
        using var module = new OpenSessionModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        using (Pkcs11Session session = new Pkcs11Slot(lowLevel, 0).OpenSession())
        {
            Assert.Equal(1, module.CallCount("C_OpenSession"));
        }

        Assert.Equal(IntPtr.Zero, module.Application);
        Assert.Equal(IntPtr.Zero, module.Notify);
    }

    private sealed class OpenSessionModule : FakeModule
    {
        public IntPtr Application { get; private set; } = -1;
        public IntPtr Notify { get; private set; } = -1;

        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            Application = application;
            Notify = notify;
            session = NewSessionHandle();
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
    }
}
