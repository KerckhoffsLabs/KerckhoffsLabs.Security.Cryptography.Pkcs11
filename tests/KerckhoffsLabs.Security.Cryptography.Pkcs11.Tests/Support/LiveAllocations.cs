using System.Collections.Concurrent;
using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Read-only access to <see cref="UnmanagedMemory"/>'s registry of live blocks (address and size), for
/// tests that check what the library lends a module: a pointer it builds into a structure must lie in a
/// live block, with its stated length inside that block.
/// </summary>
/// <remarks>
/// <para>
/// The registry is private, and reached here by reflection, so that the library ships no lookup or view
/// of it: <see cref="UnmanagedMemory.Free"/> zeroizes each block by the size recorded there, so nothing
/// outside <see cref="UnmanagedMemory"/> should be able to reach the dictionary, let alone change it. This
/// class only enumerates it.
/// </para>
/// <para>
/// The field is looked up by name and type. If <see cref="UnmanagedMemory"/> is refactored, every use fails
/// with a message naming what is missing, rather than the bounds checks passing without checking anything.
/// </para>
/// </remarks>
internal static class LiveAllocations
{
    private const string RegistryField = "_allocations";

    private static readonly Lazy<ConcurrentDictionary<IntPtr, int>> s_registry = new(FindRegistry);

    private static ConcurrentDictionary<IntPtr, int> FindRegistry()
    {
        FieldInfo field = typeof(UnmanagedMemory).GetField(RegistryField, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                $"{nameof(UnmanagedMemory)} has no private static field '{RegistryField}': update {nameof(LiveAllocations)} to its allocation registry.");
        return field.GetValue(null) as ConcurrentDictionary<IntPtr, int>
            ?? throw new InvalidOperationException(
                $"{nameof(UnmanagedMemory)}.{RegistryField} is a {field.FieldType}, not the ConcurrentDictionary<IntPtr, int> {nameof(LiveAllocations)} reads.");
    }

    /// <summary>
    /// Finds the live block that holds <paramref name="address"/>: the start and size of an allocation not
    /// yet freed whose bytes include it (a zero-size block holds only its own address). A linear scan; a
    /// block freed concurrently may or may not be found.
    /// </summary>
    /// <returns><see langword="false"/> when no live block holds the address.</returns>
    public static bool TryFind(IntPtr address, out IntPtr start, out int size)
    {
        foreach ((IntPtr block, int length) in s_registry.Value)
        {
            if ((nuint)address >= (nuint)block && (nuint)address - (nuint)block < (nuint)Math.Max(length, 1))
            {
                start = block;
                size = length;
                return true;
            }
        }

        start = IntPtr.Zero;
        size = 0;
        return false;
    }
}
