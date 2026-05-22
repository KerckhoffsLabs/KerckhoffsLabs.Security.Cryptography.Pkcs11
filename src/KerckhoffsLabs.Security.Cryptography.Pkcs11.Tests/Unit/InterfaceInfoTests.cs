using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class InterfaceInfoTests
{
    [Fact]
    public void Decodes_NameAndFlags()
    {
        var info = new InterfaceInfo("PKCS 11", (NativeCULong)CKF.CKF_INTERFACE_FORK_SAFE.Value);

        Assert.Equal("PKCS 11", info.Name);
        Assert.NotNull(info.InterfaceFlags);
        Assert.True(info.InterfaceFlags.ForkSafe);
        Assert.Equal(CKF.CKF_INTERFACE_FORK_SAFE.Value, info.InterfaceFlags.Flags);
    }

    [Fact]
    public void NoFlags_ForkSafeFalse()
    {
        var info = new InterfaceInfo("PKCS 11", (NativeCULong)0UL);
        Assert.False(info.InterfaceFlags.ForkSafe);
        Assert.Equal(0UL, info.InterfaceFlags.Flags);
    }

    [Fact]
    public void EmptyName_Preserved()
    {
        var info = new InterfaceInfo("", (NativeCULong)0UL);
        Assert.Equal("", info.Name);
    }
}
