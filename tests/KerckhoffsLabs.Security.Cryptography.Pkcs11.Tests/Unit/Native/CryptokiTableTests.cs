using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <see cref="CryptokiTable.Read"/> copies a module's function list slot by slot. It must copy exactly the
/// slots it is asked for, so a shorter (older) table is never read past its end, and never more than the
/// struct holds.
/// </summary>
public sealed class CryptokiTableTests
{
    [Theory]
    [InlineData(CryptokiTable.V32SlotCount + 1)]
    [InlineData(-1)]
    public void Read_MoreSlotsThanTheTableHolds_IsRefused(int slotCount)
    {
        IntPtr list = AllocateFullTable();
        try
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => CryptokiTable.Read(list, slotCount));
            Assert.Equal("slotCount", e.ParamName);
        }
        finally
        {
            Marshal.FreeHGlobal(list);
        }
    }

    // A full v3.2 table is in memory each time, so reading too far would find a slot and show it.
    [Theory]
    [InlineData(CryptokiTable.V240SlotCount)]
    [InlineData(CryptokiTable.V30SlotCount)]
    [InlineData(CryptokiTable.V32SlotCount)]
    public void Read_CopiesExactlyTheSlotsAskedFor(int slotCount)
    {
        IntPtr list = AllocateFullTable();
        try
        {
            CryptokiTable table = CryptokiTable.Read(list, slotCount);
            ReadOnlySpan<IntPtr> slots = Slots(ref table);

            for (int i = 0; i < CryptokiTable.V32SlotCount; i++)
                Assert.Equal(i < slotCount ? Sentinel(i) : IntPtr.Zero, slots[i]);
        }
        finally
        {
            Marshal.FreeHGlobal(list);
        }
    }

    // The bound Read checks is the struct's own size: it holds exactly the v3.2 slots.
    [Fact]
    public void TheStruct_HoldsExactlyTheV32Slots()
        => Assert.Equal(CryptokiTable.V32SlotCount * IntPtr.Size, Unsafe.SizeOf<CryptokiTable>());

    private static IntPtr AllocateFullTable()
        => NativeFunctionList.Allocate(3, 2, CryptokiTable.V32SlotCount,
            NativeFunctionList.SlotNames.Select((name, i) => (name, i)).ToDictionary(s => s.name, s => Sentinel(s.i)));

    // Never called: distinct, recognisable values only.
    private static IntPtr Sentinel(int slot) => (IntPtr)(0x0C00_0000 + (slot + 1) * 0x10);

    private static ReadOnlySpan<IntPtr> Slots(ref CryptokiTable table)
        => MemoryMarshal.Cast<CryptokiTable, IntPtr>(new Span<CryptokiTable>(ref table));
}
