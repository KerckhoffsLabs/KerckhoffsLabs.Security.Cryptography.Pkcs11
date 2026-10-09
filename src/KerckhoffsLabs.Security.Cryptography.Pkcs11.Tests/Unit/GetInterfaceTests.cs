using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11Library.GetInterface"/>: the name encoding passed to the
/// module (NUL-terminated UTF-8, or null for the default), the descriptor read-back (name + flags),
/// and the v2.40 not-supported path. The native <c>C_GetInterface</c> call itself is exercised by the
/// Integration suite over pkcs11-mock.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GetInterfaceTests
{
    // A v2.40 module: it exports no C_GetInterface.
    private sealed class V240Module : FakeModule;

    private sealed class InterfaceModule : FakeModule
    {
        public byte[]? CapturedName;
        public bool NameWasNull;
        public ulong Flags = 1; // CKF_INTERFACE_FORK_SAFE
        public string ReturnName = "PKCS 11";
        private IntPtr _namePtr;

        protected override CKR C_GetInterface(byte[]? interfaceName, NativeCULong flags, ref CK_INTERFACE iface)
        {
            NameWasNull = interfaceName is null;
            CapturedName = interfaceName;

            Marshal.FreeCoTaskMem(_namePtr);
            _namePtr = Marshal.StringToCoTaskMemUTF8(ReturnName);
            iface.InterfaceName = _namePtr;
            iface.Flags = (NativeCULong)Flags;
            return CKR.CKR_OK;
        }

        protected override void Disposing()
        {
            Marshal.FreeCoTaskMem(_namePtr);
            _namePtr = IntPtr.Zero;
        }
    }

    [Fact]
    public void GetInterface_ByName_ReturnsDescriptorAndEncodesNulTerminatedName()
    {
        using var fake = new InterfaceModule { ReturnName = "PKCS 11", Flags = 1 };
        using var lib = fake.Load();

        InterfaceInfo info = lib.GetInterface("PKCS 11");

        Assert.Equal("PKCS 11", info.Name);
        Assert.Equal(1UL, info.InterfaceFlags.Flags);
        Assert.True(info.InterfaceFlags.ForkSafe);
        Assert.Equal("PKCS 11\0"u8.ToArray(), fake.CapturedName);
    }

    [Fact]
    public void GetInterface_NullName_RequestsModuleDefault()
    {
        using var fake = new InterfaceModule { ReturnName = "Vendor X" };
        using var lib = fake.Load();

        InterfaceInfo info = lib.GetInterface();

        Assert.True(fake.NameWasNull);
        Assert.Equal("Vendor X", info.Name);
    }

    [Fact]
    public void GetInterface_NotSupported_Throws()
    {
        using var module = new V240Module();
        using var lib = module.Load();

        Assert.ThrowsAny<Pkcs11Exception>(() => lib.GetInterface("PKCS 11"));
    }
}
