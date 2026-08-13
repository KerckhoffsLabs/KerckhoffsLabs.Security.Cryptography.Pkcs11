using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
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
    /// <summary>
    /// Size in bytes of one CK_ULONG (<see cref="NativeCULong"/>) for the current build: 4 on the
    /// net10.0-windows asset, 8 on the neutral net10.0 asset (Unix-LP64). The runtime guard in
    /// <see cref="LowLevelPkcs11Library"/> ensures this matches the host's native CK_ULONG width.
    /// </summary>
    /// <remarks>
    /// Measured with <see cref="Unsafe.SizeOf{T}"/>, not <c>Marshal.SizeOf</c>: CK_ULONG crosses the
    /// boundary by value through the <c>delegate* unmanaged[Cdecl]</c> signatures, which under
    /// <c>[assembly: DisableRuntimeMarshalling]</c> use the blittable layout. <see cref="NativeCULong"/>
    /// wraps a single primitive, so both agree — but the blittable size is the one that governs here.
    /// </remarks>
    public static int NativeULongSize { get; } = Unsafe.SizeOf<NativeCULong>();

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger(typeof(UnmanagedMemory));

    /// <summary>
    /// Every allocation performed by this class, by pointer and size.
    /// </summary>
    /// <remarks>
    /// Concurrent rather than a dictionary behind a lock, and the distinction is not about
    /// throughput. <see cref="Free"/> runs on the finalizer thread — <c>ObjectAttribute</c> has a
    /// finalizer — so a process-global lock here would let one application thread holding it stall
    /// finalization for the entire process, not just for this library. <c>TryAdd</c> and
    /// <c>TryRemove</c> are atomic on their own, which is all the tracker ever needed; the lock was
    /// also serializing every attribute allocation across every session.
    /// </remarks>
    private static readonly ConcurrentDictionary<IntPtr, int> _allocations = new();

    /// <summary>
    /// When <c>true</c>, every <see cref="Allocate"/> / <see cref="Free"/> writes a debug log line.
    /// The allocation dictionary is populated <em>unconditionally</em> (independent of this flag); only
    /// the log output is gated, so toggling at runtime is safe — pointers allocated with the flag off
    /// can still be freed after it is turned on without tripping the untracked-memory check.
    /// </summary>
    public static bool DebugModeEnabled { get; set; }

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
    public static int OutstandingAllocationCount => _allocations.Count;

    /// <summary>
    /// Allocates unmanaged zero-filled memory
    /// </summary>
    /// <param name="size">Number of bytes required</param>
    /// <returns>Pointer to newly allocated unmanaged zero-filled memory</returns>
    public static IntPtr Allocate(int size)
    {
        if (size < 0)
            throw new ArgumentException("Value has to be positive number", nameof(size));

        // Allocate then zero in place. NativeMemory.Clear avoids the throwaway managed
        // byte[] the old Write(memory, new byte[size]) path allocated on every call.
        IntPtr memory = Marshal.AllocHGlobal(size);
        if (size > 0)
            unsafe { NativeMemory.Clear((void*)memory, (nuint)size); }

        if (!_allocations.TryAdd(memory, size))
        {
            // AllocHGlobal handed us a pointer the tracker thinks is already live —
            // would mean a missed Free somewhere upstream.
            throw new InvalidOperationException(
                $"Allocation tracker corrupted: {_allocations[memory]} bytes already tracked at {memory}.");
        }

        if (DebugModeEnabled)
            Log.AllocatedMemory(_logger, size, memory, _allocations.Count);

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

        // TryRemove is the atomic claim: whichever caller removes the entry owns the free, so a
        // Dispose racing a finalizer cannot double-free even without a lock around the pair.
        if (!_allocations.TryRemove(memory, out int size))
        {
            throw new InvalidOperationException(
                $"Cannot free untracked memory at {memory} — not allocated through {nameof(UnmanagedMemory)} or already freed.");
        }

        if (DebugModeEnabled)
            Log.FreeingMemory(_logger, size, memory, _allocations.Count);

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
    /// Returns the unmanaged size of the <typeparamref name="T"/> struct in bytes.
    /// For <c>[PackedForPkcs11]</c>-marked types, returns the Windows-packed sibling size on
    /// Windows and the natural size on Linux/macOS; otherwise the blittable size.
    /// </summary>
    /// <remarks>
    /// Both branches measure the blittable layout, which is the one that governs under
    /// <c>[assembly: DisableRuntimeMarshalling]</c>. Every native struct is verified to have an
    /// identical managed and marshalled layout by
    /// <c>NativeStructLayoutTests.EveryCkStruct_ManagedSizeMatchesMarshalledSize</c>, so this agrees
    /// with the <c>Marshal.StructureToPtr</c> that fills the buffer.
    /// </remarks>
    public static int SizeOf<T>() where T : unmanaged
        => IsPackedForPkcs11(typeof(T)) ? Pkcs11Marshal.SizeOf<T>() : Unsafe.SizeOf<T>();

    /// <summary>
    /// Returns the unmanaged size of the structure type <paramref name="structureType"/> in bytes.
    /// Only <c>[PackedForPkcs11]</c>-marked types are supported; use <see cref="SizeOf{T}"/> for
    /// all other types.
    /// </summary>
    /// <param name="structureType">Type of structure whose size should be determined</param>
    /// <returns>Unmanaged size of the structure in bytes</returns>
    public static int SizeOf(Type structureType)
    {
        ArgumentNullException.ThrowIfNull(structureType);
        if (!IsPackedForPkcs11(structureType))
            throw new NotSupportedException(
                $"SizeOf(Type) is only supported for [PackedForPkcs11]-marked types. Use SizeOf<T>() for '{structureType.FullName}'.");
        return Pkcs11Marshal.IsWindows
            ? PackedDispatch.SizeOfWindows(structureType)
            : PackedDispatch.SizeOfUnified(structureType);
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
    /// Marshals a <c>[PackedForPkcs11]</c>-marked struct to unmanaged memory using the
    /// correct on-wire layout for the current platform (Windows-packed sibling on Windows,
    /// natural layout on Linux/macOS).
    /// </summary>
    /// <param name="memory">Previously allocated unmanaged memory to write to</param>
    /// <param name="structure">Struct to marshal</param>
    public static void Write<T>(IntPtr memory, in T structure) where T : unmanaged
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        if (IsPackedForPkcs11(typeof(T)))
            Pkcs11Marshal.WriteStructure(memory, in structure);
        else
            Marshal.StructureToPtr(structure, memory, false);
    }

    /// <summary>
    /// Copies content of structure to unmanaged memory.
    /// Only <c>[PackedForPkcs11]</c>-marked types are supported; use <see cref="Write{T}"/> for
    /// all other types.
    /// </summary>
    /// <param name="memory">Previously allocated unmanaged memory to copy to</param>
    /// <param name="structure">Structure to copy from</param>
    public static void Write(IntPtr memory, object structure)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structure);

        if (!IsPackedForPkcs11(structure.GetType()))
            throw new NotSupportedException(
                $"Write(object) is only supported for [PackedForPkcs11]-marked types. Use Write<T>() for '{structure.GetType().FullName}'.");

        if (Pkcs11Marshal.IsWindows)
            PackedDispatch.WriteWindows(memory, structure);
        else
            PackedDispatch.WriteUnified(memory, structure);
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
    /// Reads a struct from unmanaged memory using the correct on-wire layout for the
    /// current platform. For <c>[PackedForPkcs11]</c>-marked types, uses the Windows-packed
    /// sibling on Windows and the natural layout on Linux/macOS; for all other types,
    /// delegates to <see cref="Marshal.PtrToStructure{T}(nint)"/>.
    /// </summary>
    /// <typeparam name="T">The unified struct type to read</typeparam>
    /// <param name="memory">Pointer to unmanaged memory</param>
    /// <returns>The struct read from unmanaged memory</returns>
    /// <remarks>
    /// The <c>[DynamicallyAccessedMembers]</c> constraint on <typeparamref name="T"/> satisfies
    /// the trimmer's requirement for <see cref="Marshal.PtrToStructure{T}(nint)"/> in the
    /// non-packed fallback path. Struct types always satisfy this requirement.
    /// </remarks>
    public static T Read<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] T>(IntPtr memory) where T : unmanaged
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        if (IsPackedForPkcs11(typeof(T)))
            return Pkcs11Marshal.ReadStructure<T>(memory);
        return Marshal.PtrToStructure<T>(memory);
    }

    /// <summary>
    /// Copies content of unmanaged memory to the newly allocated managed structure.
    /// Only <c>[PackedForPkcs11]</c>-marked types are supported; use <see cref="Read{T}"/> for
    /// all other types.
    /// </summary>
    /// <param name="memory">Memory that should be copied</param>
    /// <param name="structureType">Type of structure that should be created</param>
    /// <returns>Structure of requested type</returns>
    public static object? Read(IntPtr memory, Type structureType)
    {
        if (memory == IntPtr.Zero) throw new ArgumentNullException(nameof(memory));
        ArgumentNullException.ThrowIfNull(structureType);

        if (!IsPackedForPkcs11(structureType))
            throw new NotSupportedException(
                $"Read(Type) is only supported for [PackedForPkcs11]-marked types. Use Read<T>() for '{structureType.FullName}'.");

        return Pkcs11Marshal.IsWindows
            ? PackedDispatch.ReadWindows(memory, structureType)
            : PackedDispatch.ReadUnified(memory, structureType);
    }

    // ---- Private helpers ----

    /// <summary>
    /// Returns <c>true</c> when <paramref name="t"/> is decorated with
    /// <see cref="PackedForPkcs11Attribute"/>. Uses <c>Type.IsDefined</c> which
    /// only reads the metadata token — AOT-safe, no dynamic code generation required.
    /// </summary>
    private static bool IsPackedForPkcs11(Type t) =>
        t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false);
}
