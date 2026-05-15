using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.DotNet.XUnitExtensions;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

public sealed class Pkcs11MarshalTests
{
    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact]
    public void SizeOf_ReturnsNativeSize_ForCK_VERSION()
    {
        Assert.Equal(Marshal.SizeOf<CK_VERSION>(), Pkcs11Marshal.SizeOf<CK_VERSION>());
    }

    [ConditionalFact(nameof(IsUnix))]
    public void SizeOf_ForCK_INFO_MatchesMarshalSizeOf_OnUnix()
    {
        Assert.Equal(Marshal.SizeOf<CK_INFO>(), Pkcs11Marshal.SizeOf<CK_INFO>());
    }

    [Fact]
    public void RoundTrip_CK_VERSION_ThroughWriteRead()
    {
        var src = new CK_VERSION { Major = [3], Minor = [2] };
        int size = Pkcs11Marshal.SizeOf<CK_VERSION>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_VERSION>(ptr);
            Assert.Equal(3, rt.Major[0]);
            Assert.Equal(2, rt.Minor[0]);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    [Fact]
    public void RoundTrip_CK_INFO_ThroughWriteRead()
    {
        // Pre-populate the byte arrays — Marshal will reject null inline arrays.
        var src = new CK_INFO
        {
            CryptokiVersion = new CK_VERSION { Major = [3], Minor = [2] },
            ManufacturerId = new byte[32],
            Flags = default,
            LibraryDescription = new byte[32],
            LibraryVersion = new CK_VERSION { Major = [1], Minor = [0] },
        };
        for (int i = 0; i < 32; i++) src.ManufacturerId[i] = (byte)'A';

        int size = Pkcs11Marshal.SizeOf<CK_INFO>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(ptr, src);
            var rt = Pkcs11Marshal.ReadStructure<CK_INFO>(ptr);
            Assert.Equal(3, rt.CryptokiVersion.Major[0]);
            Assert.Equal(2, rt.CryptokiVersion.Minor[0]);
            Assert.Equal((byte)'A', rt.ManufacturerId[0]);
            Assert.Equal((byte)'A', rt.ManufacturerId[31]);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
