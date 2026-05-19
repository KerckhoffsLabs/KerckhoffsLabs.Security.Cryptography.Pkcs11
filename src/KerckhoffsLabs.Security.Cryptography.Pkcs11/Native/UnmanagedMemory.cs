using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Utility class that helps to manage unmanaged memory. Internal to the assembly —
/// callers needing this surface should expose the relevant lifecycle through a
/// high-level type (see <c>SecureBuffer</c>, <c>Mechanism</c>, <c>ObjectAttribute</c>).
/// Visible to the test assembly via <c>InternalsVisibleTo</c> for the leak-detection
/// harness (<see cref="OutstandingAllocationCount"/>, <see cref="DebugModeEnabled"/>).
/// </summary>
internal static class UnmanagedMemory
{
    /// <summary>Size in bytes of one CK_ULONG (NativeCULong) on the current platform: 4 on Windows, 8 on Unix-LP64.</summary>
    public static int NativeULongSize { get; } = Marshal.SizeOf<NativeCULong>();

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger(typeof(UnmanagedMemory));

    /// <summary>
    /// Lock object for list of all memory allocations
    /// </summary>
#if NET9_0_OR_GREATER
    private static readonly Lock _allocationsLock = new();
#else
    private static readonly object _allocationsLock = new();
#endif

    /// <summary>
    /// List of all memory allocations performed by this class
    /// </summary>
    private static readonly Dictionary<IntPtr, int> _allocations = [];

    /// <summary>
    /// Flag indicating whether per-allocation messages should be written to the
    /// debug log. The allocation dictionary is populated <em>unconditionally</em>
    /// (independent of this flag); only the log output is gated. Toggling this at
    /// runtime is therefore safe — pointers allocated with the flag off can still
    /// be freed after it is turned on without tripping the untracked-memory check.
    /// </summary>
    private static bool _debugModeEnabled = false;

    /// <summary>
    /// When <c>true</c>, every <see cref="Allocate"/> / <see cref="Free"/> writes a
    /// debug log line. The allocation tracker itself is always on (see <see cref="OutstandingAllocationCount"/>).
    /// </summary>
    public static bool DebugModeEnabled
    {
        get
        {
            return _debugModeEnabled;
        }
        set
        {
            _debugModeEnabled = value;
        }
    }

    /// <summary>
    /// Number of unmanaged allocations currently outstanding (allocated but not yet freed).
    /// Always accurate — the tracker dictionary is populated unconditionally so finalizer-time
    /// frees of objects created before <see cref="DebugModeEnabled"/> was toggled are still
    /// recognized as ours.
    /// </summary>
    /// <remarks>
    /// Intended for diagnostic and leak-detection tests. To measure leaks across a workload,
    /// snapshot this value before and after; do not assume it is zero between tests, since
    /// other in-process allocations may be outstanding.
    /// </remarks>
    public static int OutstandingAllocationCount
    {
        get
        {
            lock (_allocationsLock)
            {
                return _allocations.Count;
            }
        }
    }

    /// <summary>
    /// Allocates unmanaged zero-filled memory
    /// </summary>
    /// <param name="size">Number of bytes required</param>
    /// <returns>Pointer to newly allocated unmanaged zero-filled memory</returns>
    public static IntPtr Allocate(int size)
    {
        if (size < 0)
            throw new ArgumentException("Value has to be positive number", nameof(size));

        IntPtr memory = IntPtr.Zero;

        // Allocate memory and fill it with zeros
        // Note: new byte array is automaticaly filled with zeros
        memory = Marshal.AllocHGlobal(size);
        Write(memory, new byte[size]);

        lock (_allocationsLock)
        {
            if (!_allocations.TryAdd(memory, size))
            {
                // AllocHGlobal handed us a pointer the tracker thinks is already live —
                // would mean a missed Free somewhere upstream.
                throw new InvalidOperationException(
                    $"Allocation tracker corrupted: {_allocations[memory]} bytes already tracked at {memory}.");
            }

            if (_debugModeEnabled)
                _logger.LogDebug("Allocated {Size} bytes at {Address}. Allocations: {AllocationCount}", size, memory, _allocations.Count);
        }

        return memory;
    }

    /// <summary>
    /// Frees previously allocated unmanaged memory. Zeroes the buffer before releasing
    /// it so that IVs, nonces, AAD, context bytes, attribute values, and CKA_VALUE reads
    /// (including the ML-KEM extract-and-destroy path) do not linger in the unmanaged
    /// heap after the allocator reuses the block. Mirrors the
    /// <see cref="Internal.SecureBuffer"/> / <see cref="SecurePin"/> zeroize pattern.
    /// </summary>
    /// <param name="memory">Pointer to the previously allocated unmanaged memory</param>
    public static void Free(ref IntPtr memory)
    {
        if (memory == IntPtr.Zero)
            return;

        int size;
        lock (_allocationsLock)
        {
            if (!_allocations.Remove(memory, out size))
            {
                throw new InvalidOperationException(
                    $"Cannot free untracked memory at {memory} — not allocated through {nameof(UnmanagedMemory)} or already freed.");
            }

            if (_debugModeEnabled)
                _logger.LogDebug("Freeing {Size} bytes at {Address}. Allocations: {AllocationCount}", size, memory, _allocations.Count);
        }

        Zeroize(memory, size);
        Marshal.FreeHGlobal(memory);
        memory = IntPtr.Zero;
    }

    /// <summary>
    /// Zeroes <paramref name="size"/> bytes of unmanaged memory at <paramref name="memory"/>
    /// using <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> — guaranteed not to
    /// be elided by the JIT.
    /// </summary>
    /// <remarks>
    /// Internal seam exposed for the zero-on-free regression test; production code should go
    /// through <see cref="Free"/>.
    /// </remarks>
    internal static void Zeroize(IntPtr memory, int size)
    {
        if (memory == IntPtr.Zero || size <= 0) return;
        unsafe { CryptographicOperations.ZeroMemory(new Span<byte>((void*)memory, size)); }
    }

    /// <summary>
    /// Returns the unmanaged size of the structure in bytes
    /// </summary>
    /// <param name="structureType">Type of structure whose size should be determined</param>
    /// <returns>Unmanaged size of the structure in bytes</returns>
    public static int SizeOf(Type structureType)
    {
        ArgumentNullException.ThrowIfNull(structureType);
        // For [PackedForPkcs11]-marked types, dispatch to the platform-appropriate sibling.
        // For all other types, fall through to Marshal.SizeOf.
        if (structureType.IsValueType && IsPackedForPkcs11(structureType))
            return SizeOfPacked(structureType);
        return Marshal.SizeOf(structureType);
    }

    /// <summary>
    /// Copies content of byte array to unmanaged memory
    /// </summary>
    /// <param name="memory">Previously allocated unmanaged memory to copy to</param>
    /// <param name="content">Byte array to copy from</param>
    public static void Write(IntPtr memory, byte[] content)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        ArgumentNullException.ThrowIfNull(content);

        Marshal.Copy(content, 0, memory, content.Length);
    }

    /// <summary>
    /// Copies content of a read-only byte span to unmanaged memory
    /// </summary>
    /// <param name="memory">Previously allocated unmanaged memory to copy to</param>
    /// <param name="data">Data to copy from</param>
    public static void Write(IntPtr memory, ReadOnlySpan<byte> data)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        unsafe { fixed (byte* src = data) Buffer.MemoryCopy(src, (void*)memory, data.Length, data.Length); }
    }

    /// <summary>
    /// Copies content of structure to unmanaged memory
    /// </summary>
    /// <param name="memory">Previously allocated unmanaged memory to copy to</param>
    /// <param name="structure">Structure to copy from</param>
    public static void Write(IntPtr memory, object structure)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structure);

        if (IsPackedForPkcs11(structure.GetType()))
            WritePacked(memory, structure);
        else
            Marshal.StructureToPtr(structure, memory, false);
    }

    /// <summary>
    /// Creates copy of unmanaged memory contet
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="size">Number of bytes that should be copied</param>
    /// <returns>Copy of unmanaged memory contet</returns>
    public static byte[] Read(IntPtr memory, int size)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        if (size < 0)
            throw new ArgumentException("Value has to be positive number", nameof(size));

        byte[] output = new byte[size];
        Marshal.Copy(memory, output, 0, size);
        return output;
    }

    /// <summary>
    /// Copies content of unmanaged memory into the provided byte array
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="destination">Byte array to copy into; length determines number of bytes copied</param>
    public static void Read(IntPtr memory, byte[] destination)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        ArgumentNullException.ThrowIfNull(destination);

        Marshal.Copy(memory, destination, 0, destination.Length);
    }

    /// <summary>
    /// Copies content of unmanaged memory into the provided byte span
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="destination">Span to copy into; length determines number of bytes copied</param>
    public static void Read(IntPtr memory, Span<byte> destination)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        unsafe { fixed (byte* dst = destination) Buffer.MemoryCopy((void*)memory, dst, destination.Length, destination.Length); }
    }

    /// <summary>
    /// Copies content of unmanaged memory to the newly allocated managed structure
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="structureType">Type of structure that should be created</param>
    /// <returns>Structure of requested type</returns>
    public static object? Read(IntPtr memory, Type structureType)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structureType);

        if (structureType.IsValueType && IsPackedForPkcs11(structureType))
            return ReadPacked(memory, structureType);
        return Marshal.PtrToStructure(memory, structureType);
    }

    /// <summary>
    /// Copies content of unmanaged memory to the existing managed structure
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="structure">Object to which data should be copied</param>
    public static void Read(IntPtr memory, object structure)
    {
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        ArgumentNullException.ThrowIfNull(structure);

        Marshal.PtrToStructure(memory, structure);
    }

    // ---- Packed-struct dispatch helpers ----

    private static bool IsPackedForPkcs11(Type t) =>
        t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false);

    private static int SizeOfPacked(Type t)
    {
        var winType = Pkcs11Marshal.IsWindows
            ? t.Assembly.GetType(t.FullName + "_Windows")
            : null;
        return Marshal.SizeOf(winType ?? t);
    }

    private static void WritePacked(IntPtr memory, object structure)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            var winType = structure.GetType().Assembly.GetType(structure.GetType().FullName + "_Windows");
            if (winType is not null)
            {
                var fromUnified = winType.GetMethod("FromUnified",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
                if (fromUnified is not null)
                {
                    object windowsBoxed = fromUnified.Invoke(null, [structure])!;
                    Marshal.StructureToPtr(windowsBoxed, memory, false);
                    return;
                }
            }
        }
        Marshal.StructureToPtr(structure, memory, false);
    }

    private static object? ReadPacked(IntPtr memory, Type t)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            var winType = t.Assembly.GetType(t.FullName + "_Windows");
            if (winType is not null)
            {
                object? winBoxed = Marshal.PtrToStructure(memory, winType);
                if (winBoxed is null) return null;
                var toUnified = winType.GetMethod("ToUnified",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
                return toUnified?.Invoke(winBoxed, null);
            }
        }
        return Marshal.PtrToStructure(memory, t);
    }
}