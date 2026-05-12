using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class UnmanagedMemoryHarnessTests : IDisposable
{
    private readonly bool _wasDebug;

    public UnmanagedMemoryHarnessTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose()
    {
        UnmanagedMemory.DebugModeEnabled = _wasDebug;
    }

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
}
