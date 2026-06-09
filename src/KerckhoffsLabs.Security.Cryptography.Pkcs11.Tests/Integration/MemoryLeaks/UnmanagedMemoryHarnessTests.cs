using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class UnmanagedMemoryHarnessTests : IDisposable
{
    private readonly bool _wasDebug;

    public UnmanagedMemoryHarnessTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void OutstandingAllocationCount_IsAccessible()
    {
        int count = UnmanagedMemory.OutstandingAllocationCount;
        Assert.True(count >= 0);
    }

    [Fact]
    public void OutstandingAllocationCount_TracksAllocateAndFree()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        IntPtr ptr = UnmanagedMemory.Allocate(16);
        try
        {
            Assert.Equal(baseline + 1, UnmanagedMemory.OutstandingAllocationCount);
        }
        finally
        {
            UnmanagedMemory.Free(ref ptr);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void Zeroize_ClearsSentinelBytes()
    {
        const int size = 64;
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            byte[] sentinel = new byte[size];
            sentinel.AsSpan().Fill(0xAA);
            Marshal.Copy(sentinel, 0, ptr, size);

            byte[] before = new byte[size];
            Marshal.Copy(ptr, before, 0, size);
            Assert.All(before, b => Assert.Equal((byte)0xAA, b));

            UnmanagedMemory.Zeroize(ptr, size);

            byte[] after = new byte[size];
            Marshal.Copy(ptr, after, 0, size);
            Assert.All(after, b => Assert.Equal((byte)0, b));
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    [Fact]
    public void Zeroize_IsNoopOnZeroPointerOrZeroSize()
    {
        UnmanagedMemory.Zeroize(IntPtr.Zero, 64);

        IntPtr ptr = Marshal.AllocHGlobal(16);
        try
        {
            byte[] sentinel = new byte[16];
            sentinel.AsSpan().Fill(0xCC);
            Marshal.Copy(sentinel, 0, ptr, 16);

            UnmanagedMemory.Zeroize(ptr, 0);

            byte[] after = new byte[16];
            Marshal.Copy(ptr, after, 0, 16);
            Assert.All(after, b => Assert.Equal((byte)0xCC, b));
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }
}
