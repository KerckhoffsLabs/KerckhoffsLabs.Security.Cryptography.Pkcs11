using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11Library.GetInterface"/>: the name encoding passed to the
/// module (NUL-terminated UTF-8, or null for the default), the descriptor read-back (name + flags),
/// and the v2.40 not-supported path. The native <c>C_GetInterface</c> call itself is exercised by the
/// Integration suite over pkcs11-mock.
/// </summary>
public sealed class GetInterfaceTests
{
    private sealed class InterfaceFake : NotSupportedPkcs11Library
    {
        public byte[]? CapturedName;
        public bool NameWasNull;
        public ulong Flags = 1; // CKF_INTERFACE_FORK_SAFE
        public string ReturnName = "PKCS 11";
        public CKR Rv = CKR.CKR_OK;
        private IntPtr _namePtr;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface)
        {
            NameWasNull = interfaceName.IsEmpty;
            CapturedName = interfaceName.ToArray();
            iface = default;
            if (Rv != CKR.CKR_OK) return Rv;

            _namePtr = Marshal.StringToCoTaskMemUTF8(ReturnName);
            iface = new CK_INTERFACE { InterfaceName = _namePtr, FunctionList = 0x1234, Flags = (NativeCULong)Flags };
            return CKR.CKR_OK;
        }

        public override void Dispose()
        {
            // Idempotent: Pkcs11Library owns and disposes this fake, and the test's `using` disposes
            // it again — a non-idempotent free would double-free the name buffer and crash the host.
            if (_namePtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(_namePtr);
                _namePtr = IntPtr.Zero;
            }
            base.Dispose();
        }
    }

    [Fact]
    public void GetInterface_ByName_ReturnsDescriptorAndEncodesNulTerminatedName()
    {
        using var fake = new InterfaceFake { ReturnName = "PKCS 11", Flags = 1 };
        using var lib = new Pkcs11Library(fake);

        InterfaceInfo info = lib.GetInterface("PKCS 11");

        Assert.Equal("PKCS 11", info.Name);
        Assert.Equal(1UL, info.InterfaceFlags.Flags);
        Assert.True(info.InterfaceFlags.ForkSafe);
        Assert.Equal("PKCS 11\0"u8.ToArray(), fake.CapturedName);
    }

    [Fact]
    public void GetInterface_NullName_RequestsModuleDefault()
    {
        using var fake = new InterfaceFake { ReturnName = "Vendor X" };
        using var lib = new Pkcs11Library(fake);

        InterfaceInfo info = lib.GetInterface();

        Assert.True(fake.NameWasNull);
        Assert.Equal("Vendor X", info.Name);
    }

    [Fact]
    public void GetInterface_NotSupported_Throws()
    {
        using var fake = new InterfaceFake { Rv = CKR.CKR_FUNCTION_NOT_SUPPORTED };
        using var lib = new Pkcs11Library(fake);

        Assert.ThrowsAny<Pkcs11Exception>(() => lib.GetInterface("PKCS 11"));
    }
}
