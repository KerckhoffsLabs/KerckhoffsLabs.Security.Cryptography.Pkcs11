using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>Which end of a <see cref="GuardedMemory"/> buffer touches its no-access page.</summary>
public enum GuardSide
{
    /// <summary>The byte after the last one is inaccessible: catches a read or write past the end.</summary>
    After,

    /// <summary>The byte before the first one is inaccessible: catches a read or write before the start.</summary>
    Before,
}

/// <summary>
/// A buffer placed flush against a page the process may not touch, so that a native module reading or
/// writing even one byte outside it faults at once, instead of silently using whatever lies next to it.
/// </summary>
/// <remarks>
/// <para>
/// AddressSanitizer does not see the managed heap, and the GC's own heap verification misses an overrun
/// that stays within an object's padding, so a pinned <c>byte[]</c> cannot show a short overrun. This
/// memory comes straight from the OS (<c>mmap</c>/<c>VirtualAlloc</c>), with the guard page set to
/// <c>PROT_NONE</c>/<c>PAGE_NOACCESS</c>, and is exact to the byte on every platform.
/// </para>
/// <para>
/// A fault ends the test process: an access violation in native code, or in an
/// <c>[UnmanagedCallersOnly]</c> fake module, cannot be caught. That is the point: the run fails loudly,
/// with the faulting stack, instead of passing over corrupted memory.
/// </para>
/// </remarks>
internal sealed unsafe partial class GuardedMemory : IDisposable
{
    private readonly IntPtr _mapping;
    private readonly nuint _mappingSize;
    private bool _disposed;

    private GuardedMemory(IntPtr mapping, nuint mappingSize, IntPtr address, IntPtr guard, int length)
    {
        _mapping = mapping;
        _mappingSize = mappingSize;
        Address = address;
        GuardPage = guard;
        Length = length;
    }

    /// <summary>The first byte of the buffer.</summary>
    public IntPtr Address { get; }

    /// <summary>The start of the inaccessible page next to the buffer.</summary>
    public IntPtr GuardPage { get; }

    public int Length { get; }

    /// <summary>The buffer. Valid until <see cref="Dispose"/>.</summary>
    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new Span<byte>((void*)Address, Length);
        }
    }

    /// <summary>Allocates <paramref name="length"/> zeroed bytes with a guard page on <paramref name="side"/>.</summary>
    public static GuardedMemory Allocate(int length, GuardSide side = GuardSide.After)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        int page = Environment.SystemPageSize;
        int dataPages = Math.Max(1, (length + page - 1) / page);
        nuint size = (nuint)((dataPages + 1) * page);

        IntPtr mapping = Map(size);
        IntPtr guard = side == GuardSide.After ? mapping + dataPages * page : mapping;
        try
        {
            Protect(guard, (nuint)page);
        }
        catch
        {
            Unmap(mapping, size);
            throw;
        }

        IntPtr address = side == GuardSide.After ? guard - length : guard + page;
        return new GuardedMemory(mapping, size, address, guard, length);
    }

    /// <summary>Allocates a copy of <paramref name="contents"/>.</summary>
    public static GuardedMemory Of(ReadOnlySpan<byte> contents, GuardSide side = GuardSide.After)
    {
        GuardedMemory memory = Allocate(contents.Length, side);
        contents.CopyTo(memory.Span);
        return memory;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Unmap(_mapping, _mappingSize);
    }

    /// <summary>
    /// Whether the process may read the byte at <paramref name="address"/>, found out without touching it:
    /// on Unix the kernel copies it into a pipe and answers <c>EFAULT</c> instead of faulting; on Windows
    /// <c>VirtualQuery</c> reports the page's protection.
    /// </summary>
    public static bool IsReadable(IntPtr address)
    {
        if (OperatingSystem.IsWindows())
        {
            MemoryBasicInformation info;
            if (VirtualQuery(address, &info, (nuint)sizeof(MemoryBasicInformation)) == 0)
                throw new InvalidOperationException($"VirtualQuery failed ({Marshal.GetLastPInvokeError()}).");
            return info.State == MemCommit && (info.Protect & (PageNoAccess | PageGuard)) == 0;
        }

        int* fds = stackalloc int[2];
        bool mac = OperatingSystem.IsMacOS();
        if ((mac ? PipeMacOS(fds) : Pipe(fds)) != 0)
            throw new InvalidOperationException($"pipe failed (errno {Marshal.GetLastPInvokeError()}).");
        try
        {
            nint written = mac ? WriteMacOS(fds[1], address, 1) : Write(fds[1], address, 1);
            if (written == 1)
                return true;
            int errno = Marshal.GetLastPInvokeError();
            return errno == EFault
                ? false
                : throw new InvalidOperationException($"write failed (errno {errno}).");
        }
        finally
        {
            if (mac) { CloseMacOS(fds[0]); CloseMacOS(fds[1]); }
            else { Close(fds[0]); Close(fds[1]); }
        }
    }

    // -----------------------------------------------------------------------
    // OS page mapping
    // -----------------------------------------------------------------------

    private const int ProtNone = 0, ProtRead = 1, ProtWrite = 2;
    private const int MapPrivate = 0x02;
    private const int MapAnonymousLinux = 0x20, MapAnonymousMacOS = 0x1000;
    private const uint MemCommit = 0x1000, MemReserve = 0x2000, MemRelease = 0x8000;
    private const uint PageReadWrite = 0x04, PageNoAccess = 0x01, PageGuard = 0x100;
    private const int EFault = 14; // Linux and macOS alike

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private static IntPtr Map(nuint size)
    {
        IntPtr p;
        if (OperatingSystem.IsWindows())
        {
            p = VirtualAlloc(IntPtr.Zero, size, MemCommit | MemReserve, PageReadWrite);
            if (p == IntPtr.Zero)
                throw new OutOfMemoryException($"VirtualAlloc of {size} bytes failed ({Marshal.GetLastPInvokeError()}).");
            return p;
        }

        int flags = MapPrivate | (OperatingSystem.IsMacOS() ? MapAnonymousMacOS : MapAnonymousLinux);
        p = OperatingSystem.IsMacOS()
            ? MmapMacOS(IntPtr.Zero, size, ProtRead | ProtWrite, flags, -1, 0)
            : Mmap(IntPtr.Zero, size, ProtRead | ProtWrite, flags, -1, 0);
        if (p == -1)
            throw new OutOfMemoryException($"mmap of {size} bytes failed (errno {Marshal.GetLastPInvokeError()}).");
        return p;
    }

    private static void Protect(IntPtr page, nuint size)
    {
        bool ok = OperatingSystem.IsWindows()
            ? VirtualProtect(page, size, PageNoAccess, out _)
            : (OperatingSystem.IsMacOS() ? MprotectMacOS(page, size, ProtNone) : Mprotect(page, size, ProtNone)) == 0;
        if (!ok)
            throw new InvalidOperationException($"Could not make the guard page inaccessible ({Marshal.GetLastPInvokeError()}).");
    }

    private static void Unmap(IntPtr mapping, nuint size)
    {
        if (OperatingSystem.IsWindows())
            VirtualFree(mapping, 0, MemRelease);
        else if (OperatingSystem.IsMacOS())
            MunmapMacOS(mapping, size);
        else
            Munmap(mapping, size);
    }

    [LibraryImport("libc", EntryPoint = "mmap", SetLastError = true)]
    private static partial IntPtr Mmap(IntPtr addr, nuint length, int prot, int flags, int fd, nint offset);

    [LibraryImport("libc", EntryPoint = "mprotect", SetLastError = true)]
    private static partial int Mprotect(IntPtr addr, nuint length, int prot);

    [LibraryImport("libc", EntryPoint = "munmap", SetLastError = true)]
    private static partial int Munmap(IntPtr addr, nuint length);

    [LibraryImport("libSystem.dylib", EntryPoint = "mmap", SetLastError = true)]
    private static partial IntPtr MmapMacOS(IntPtr addr, nuint length, int prot, int flags, int fd, nint offset);

    [LibraryImport("libSystem.dylib", EntryPoint = "mprotect", SetLastError = true)]
    private static partial int MprotectMacOS(IntPtr addr, nuint length, int prot);

    [LibraryImport("libSystem.dylib", EntryPoint = "munmap", SetLastError = true)]
    private static partial int MunmapMacOS(IntPtr addr, nuint length);

    [LibraryImport("libc", EntryPoint = "pipe", SetLastError = true)]
    private static partial int Pipe(int* fds);

    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    private static partial nint Write(int fd, IntPtr buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int fd);

    [LibraryImport("libSystem.dylib", EntryPoint = "pipe", SetLastError = true)]
    private static partial int PipeMacOS(int* fds);

    [LibraryImport("libSystem.dylib", EntryPoint = "write", SetLastError = true)]
    private static partial nint WriteMacOS(int fd, IntPtr buffer, nuint count);

    [LibraryImport("libSystem.dylib", EntryPoint = "close", SetLastError = true)]
    private static partial int CloseMacOS(int fd);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nuint VirtualQuery(IntPtr address, MemoryBasicInformation* buffer, nuint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr VirtualAlloc(IntPtr address, nuint size, uint allocationType, uint protect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualProtect(IntPtr address, nuint size, uint newProtect, out uint oldProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualFree(IntPtr address, nuint size, uint freeType);
}
