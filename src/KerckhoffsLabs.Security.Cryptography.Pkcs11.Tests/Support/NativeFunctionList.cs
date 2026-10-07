using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Writes a native <c>CK_FUNCTION_LIST</c> (of any version) the way a module exports one: a
/// <c>CK_VERSION</c> header, then one function pointer per slot, in <see cref="CryptokiTable"/>'s slot
/// order. The offsets used here are the ones <see cref="CryptokiTable.Read"/> reads; that both match the C
/// compiler's layout of the OASIS headers is checked separately, by <c>AbiOracleTests</c>.
/// </summary>
internal static class NativeFunctionList
{
    /// <summary>Every slot name, in table order: the v2.40 slots, then the v3.0 additions, then the v3.2 ones.</summary>
    public static IReadOnlyList<string> SlotNames { get; } =
        [.. typeof(CryptokiTable).GetFields(BindingFlags.Instance | BindingFlags.Public).Select(f => f.Name)];

    /// <summary>Bytes a table of <paramref name="slotCount"/> slots occupies.</summary>
    public static int SizeOf(int slotCount) => CryptokiTable.FirstSlotOffset + slotCount * IntPtr.Size;

    /// <summary>Allocates (with <see cref="Marshal.AllocHGlobal(int)"/>) and writes a table; slots not in <paramref name="slots"/> are NULL.</summary>
    public static IntPtr Allocate(byte major, byte minor, int slotCount, IReadOnlyDictionary<string, IntPtr> slots)
    {
        IntPtr memory = Marshal.AllocHGlobal(SizeOf(slotCount));
        Write(memory, major, minor, slotCount, slots);
        return memory;
    }

    public static unsafe void Write(IntPtr memory, byte major, byte minor, int slotCount, IReadOnlyDictionary<string, IntPtr> slots)
    {
        string[] beyond = [.. slots.Keys.Where(name => SlotNames.Take(slotCount).All(n => n != name))];
        if (beyond.Length > 0)
            throw new ArgumentException($"Not slots of a {slotCount}-slot table: {string.Join(", ", beyond)}", nameof(slots));

        new Span<byte>((void*)memory, SizeOf(slotCount)).Clear();
        *(CK_VERSION*)memory = new CK_VERSION { Major = major, Minor = minor };
        byte* first = (byte*)memory + CryptokiTable.FirstSlotOffset;
        for (int i = 0; i < slotCount; i++)
            Unsafe.WriteUnaligned(first + i * IntPtr.Size, slots.GetValueOrDefault(SlotNames[i]));
    }
}
