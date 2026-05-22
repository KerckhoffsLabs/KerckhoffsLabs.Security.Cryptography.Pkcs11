using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SlotFlagsTests
{
    private static readonly (string Name, ulong Bit, Func<SlotFlags, bool> Get)[] All =
    [
        (nameof(SlotFlags.TokenPresent), CKF.CKF_TOKEN_PRESENT.Value, f => f.TokenPresent),
        (nameof(SlotFlags.RemovableDevice), CKF.CKF_REMOVABLE_DEVICE.Value, f => f.RemovableDevice),
        (nameof(SlotFlags.HardwareSlot), CKF.CKF_HW_SLOT.Value, f => f.HardwareSlot),
    ];

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            var flags = new SlotFlags((NativeCULong)bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        var flags = new SlotFlags((NativeCULong)0UL);
        Assert.Equal(0UL, flags.Flags);
        Assert.All(All, e => Assert.False(e.Get(flags)));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        var flags = new SlotFlags((NativeCULong)all);
        Assert.All(All, e => Assert.True(e.Get(flags)));
    }

    [Fact]
    public void Flags_ExposesRawValue()
    {
        var flags = new SlotFlags((NativeCULong)0x1234UL);
        Assert.Equal(0x1234UL, flags.Flags);
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new SlotFlags((NativeCULong)5UL), new SlotFlags((NativeCULong)5UL));
        Assert.NotEqual(new SlotFlags((NativeCULong)5UL), new SlotFlags((NativeCULong)1UL));
    }
}
