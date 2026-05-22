namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Shared contract for the CKF-backed flag records (<c>SlotFlags</c>, <c>TokenFlags</c>,
/// <c>SessionFlags</c>, <c>MechanismFlags</c>, <c>InterfaceFlags</c>). A subclass supplies only the
/// factory, the raw-value accessor, and the (name, bit, getter) table; the bit-isolation, all-set,
/// none-set, raw-value, and value-equality checks live here once.
/// </summary>
public abstract class FlagsContract<T> where T : notnull
{
    /// <summary>Constructs the flags record from a raw bitmask.</summary>
    protected abstract T Make(ulong bits);

    /// <summary>Reads back the record's raw <c>Flags</c> value.</summary>
    protected abstract ulong RawValueOf(T flags);

    /// <summary>Each bit property paired with the CKF bit it must read. Because every CKF_* is a
    /// distinct bit, this table also asserts no two properties alias the same bit.</summary>
    protected abstract (string Name, ulong Bit, Func<T, bool> Get)[] All { get; }

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            T flags = Make(bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        T flags = Make(0UL);
        Assert.Equal(0UL, RawValueOf(flags));
        Assert.All(All, e => Assert.False(e.Get(flags), e.Name));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        T flags = Make(all);
        Assert.All(All, e => Assert.True(e.Get(flags), e.Name));
    }

    [Fact]
    public void Flags_ExposesRawValue() => Assert.Equal(0x1234UL, RawValueOf(Make(0x1234UL)));

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(Make(5UL), Make(5UL));
        Assert.NotEqual(Make(5UL), Make(1UL));
    }
}
