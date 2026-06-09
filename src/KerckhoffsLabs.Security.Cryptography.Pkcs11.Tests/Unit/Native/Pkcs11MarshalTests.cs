using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

public sealed class Pkcs11MarshalTests
{
    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact]
    public void IsWindows_ReflectsOperatingSystem() => Assert.Equal(OperatingSystem.IsWindows(), Pkcs11Marshal.IsWindows);

    [Fact]
    public void SizeOf_ReturnsNativeSize_ForCK_VERSION() =>
        // CK_VERSION is not [PackedForPkcs11] -> always the natural Marshal size, both platforms.
        Assert.Equal(Marshal.SizeOf<CK_VERSION>(), Pkcs11Marshal.SizeOf<CK_VERSION>());

    [ConditionalFact(nameof(IsUnix))]
    public void SizeOf_ForCK_INFO_MatchesMarshalSizeOf_OnUnix() => Assert.Equal(Marshal.SizeOf<CK_INFO>(), Pkcs11Marshal.SizeOf<CK_INFO>());

    [Fact]
    public void RoundTrip_CK_VERSION_ThroughWriteRead()
    {
        var src = new CK_VERSION { Major = 3, Minor = 2 };
        int size = Pkcs11Marshal.SizeOf<CK_VERSION>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_VERSION>(ptr);
            Assert.Equal(3, rt.Major);
            Assert.Equal(2, rt.Minor);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    [Fact]
    public void RoundTrip_CK_INFO_ThroughWriteRead()
    {
        var src = new CK_INFO
        {
            CryptokiVersion = new CK_VERSION { Major = 3, Minor = 2 },
            Flags = default,
            LibraryVersion = new CK_VERSION { Major = 1, Minor = 0 },
        };
        for (int i = 0; i < 32; i++) src.ManufacturerId[i] = (byte)'A';

        int size = Pkcs11Marshal.SizeOf<CK_INFO>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_INFO>(ptr);
            Assert.Equal(3, rt.CryptokiVersion.Major);
            Assert.Equal(2, rt.CryptokiVersion.Minor);
            Assert.Equal((byte)'A', rt.ManufacturerId[0]);
            Assert.Equal((byte)'A', rt.ManufacturerId[31]);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    // CK_MECHANISM_INFO is [PackedForPkcs11] and all-NativeCULong (a different shape than CK_INFO's
    // inline char buffers) — exercises CK_ULONG-width marshalling through the dispatcher.
    [Fact]
    public void RoundTrip_CK_MECHANISM_INFO_ThroughWriteRead()
    {
        var src = new CK_MECHANISM_INFO
        {
            MinKeySize = (NativeCULong)128UL,
            MaxKeySize = (NativeCULong)256UL,
            Flags = (NativeCULong)0x501UL,
        };
        int size = Pkcs11Marshal.SizeOf<CK_MECHANISM_INFO>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_MECHANISM_INFO>(ptr);
            Assert.Equal(128UL, (ulong)rt.MinKeySize);
            Assert.Equal(256UL, (ulong)rt.MaxKeySize);
            Assert.Equal(0x501UL, (ulong)rt.Flags);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    [ConditionalFact(nameof(IsUnix))]
    public void SizeOf_ForCK_MECHANISM_INFO_MatchesMarshalSizeOf_OnUnix() => Assert.Equal(Marshal.SizeOf<CK_MECHANISM_INFO>(), Pkcs11Marshal.SizeOf<CK_MECHANISM_INFO>());

    [Fact]
    public void WriteStructure_OverwritesPreviousContent()
    {
        int size = Pkcs11Marshal.SizeOf<CK_VERSION>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, new CK_VERSION { Major = 9, Minor = 9 });
            Pkcs11Marshal.WriteStructure(ptr, new CK_VERSION { Major = 1, Minor = 2 });
            var rt = Pkcs11Marshal.ReadStructure<CK_VERSION>(ptr);
            Assert.Equal(1, rt.Major);
            Assert.Equal(2, rt.Minor);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
