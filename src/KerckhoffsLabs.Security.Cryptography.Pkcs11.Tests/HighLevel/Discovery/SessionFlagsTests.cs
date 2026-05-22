using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

public sealed class SessionFlagsTests
{
    private static readonly (string Name, ulong Bit, Func<SessionFlags, bool> Get)[] All =
    [
        (nameof(SessionFlags.RwSession), CKF.CKF_RW_SESSION.Value, f => f.RwSession),
        (nameof(SessionFlags.SerialSession), CKF.CKF_SERIAL_SESSION.Value, f => f.SerialSession),
    ];

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            var flags = new SessionFlags((NativeCULong)bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        var flags = new SessionFlags((NativeCULong)0UL);
        Assert.Equal(0UL, flags.Flags);
        Assert.All(All, e => Assert.False(e.Get(flags)));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        var flags = new SessionFlags((NativeCULong)all);
        Assert.All(All, e => Assert.True(e.Get(flags)));
    }

    [Fact]
    public void Flags_ExposesRawValue()
    {
        var flags = new SessionFlags((NativeCULong)0x1234UL);
        Assert.Equal(0x1234UL, flags.Flags);
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new SessionFlags((NativeCULong)6UL), new SessionFlags((NativeCULong)6UL));
        Assert.NotEqual(new SessionFlags((NativeCULong)6UL), new SessionFlags((NativeCULong)2UL));
    }
}
