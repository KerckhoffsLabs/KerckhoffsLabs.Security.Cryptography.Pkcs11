using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Utility class that helps to manage unmanaged memory
/// </summary>
public static class UnmanagedMemory
{
    /// <summary>Size in bytes of one CK_ULONG (NativeCULong) on the current platform: 4 on Windows, 8 on Unix-LP64.</summary>
    public static int NativeULongSize { get; } = Marshal.SizeOf<NativeCULong>();

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly Pkcs11InteropLogger _logger = Pkcs11InteropLoggerFactory.GetLogger(typeof(UnmanagedMemory));

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
    /// Flag indicating whether all memory allocations should be logged
    /// </summary>
    private static bool _debugModeEnabled = false;

    /// <summary>
    /// Flag indicating whether all memory allocations should be logged
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

        if (_debugModeEnabled)
        {
            lock (_allocationsLock)
            {
                if (!_allocations.ContainsKey(memory))
                {
                    _allocations.Add(memory, size);

                    _logger.Debug("Allocated {0} bytes at {1}. Allocations: {2}", size, memory, _allocations.Count);
                }
                else
                {
                    throw new Exception(string.Format("Already allocated {0} bytes at {1}", _allocations[memory], memory));
                }
            }
        }

        return memory;
    }

    /// <summary>
    /// Frees previously allocated unmanaged memory
    /// </summary>
    /// <param name="memory">Pointer to the previously allocated unmanaged memory</param>
    public static void Free(ref IntPtr memory)
    {
        if (memory == IntPtr.Zero)
            return;

        if (_debugModeEnabled)
        {
            lock (_allocations)
            {
                if (_allocations.ContainsKey(memory))
                {
                    int size = _allocations[memory];
                    _allocations.Remove(memory);

                    _logger.Debug("Freeing {0} bytes at {1}. Allocations: {2}", size, memory, _allocations.Count);
                }
                else
                {
                    throw new Exception(string.Format("Unable to free previously unallocated memory at {0}", memory));
                }
            }
        }

        Marshal.FreeHGlobal(memory);
        memory = IntPtr.Zero;
    }

    /// <summary>
    /// Returns the unmanaged size of the structure in bytes
    /// </summary>
    /// <param name="structureType">Type of structure whose size should be determined</param>
    /// <returns>Unmanaged size of the structure in bytes</returns>
    public static int SizeOf(Type structureType)
    {
        ArgumentNullException.ThrowIfNull(structureType);

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
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        ArgumentNullException.ThrowIfNull(structure);

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
        if (memory == IntPtr.Zero)
            throw new ArgumentNullException(nameof(memory));

        ArgumentNullException.ThrowIfNull(structureType);

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
}