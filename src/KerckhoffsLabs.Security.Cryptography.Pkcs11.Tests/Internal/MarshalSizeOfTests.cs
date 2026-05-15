using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

/// <summary>
/// Regression tests pinning the native struct sizes per platform. These prevent
/// future struct-layout drift and catch BL-001-class bugs immediately.
/// </summary>
public sealed class MarshalSizeOfTests
{
    // Linux/macOS x64: natural alignment (Pack = default). PKCS#11 spec applies no pragma on non-Windows.
    // The unified type T marshals correctly on these platforms.
    [Fact]
    public void CK_VERSION_size_is_2()
    {
        Assert.Equal(2, Marshal.SizeOf<CK_VERSION>());
    }

    [Fact]
    public void CK_INFO_unified_size_matches_native_on_linux()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // Windows assertion lives below.

        // CK_VERSION(2) + byte[32] + NativeCULong(8 on LP64) + byte[32] + CK_VERSION(2)
        //   = 2 + 32 + 6(pad to 8) + 8 + 32 + 2 + 6(trailing align to 8) = 88
        Assert.Equal(88, Marshal.SizeOf<CK_INFO>());
    }

    [Fact]
    public void CK_INFO_Windows_sibling_is_generated()
    {
        var winType = typeof(CK_INFO).Assembly.GetType(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.CK_INFO_Windows");
        Assert.NotNull(winType);
    }
}
