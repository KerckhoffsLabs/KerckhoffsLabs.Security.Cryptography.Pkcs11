using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

public sealed class InterfaceFlagsTests
{
    private static readonly (string Name, ulong Bit, Func<InterfaceFlags, bool> Get)[] All =
    [
        (nameof(InterfaceFlags.ForkSafe), CKF.CKF_INTERFACE_FORK_SAFE.Value, f => f.ForkSafe),
    ];

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            var flags = new InterfaceFlags((NativeCULong)bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        var flags = new InterfaceFlags((NativeCULong)0UL);
        Assert.Equal(0UL, flags.Flags);
        Assert.All(All, e => Assert.False(e.Get(flags)));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        var flags = new InterfaceFlags((NativeCULong)all);
        Assert.All(All, e => Assert.True(e.Get(flags)));
    }

    [Fact]
    public void Flags_ExposesRawValue()
    {
        var flags = new InterfaceFlags((NativeCULong)0x1234UL);
        Assert.Equal(0x1234UL, flags.Flags);
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new InterfaceFlags((NativeCULong)1UL), new InterfaceFlags((NativeCULong)1UL));
        Assert.NotEqual(new InterfaceFlags((NativeCULong)1UL), new InterfaceFlags((NativeCULong)0UL));
    }
}
