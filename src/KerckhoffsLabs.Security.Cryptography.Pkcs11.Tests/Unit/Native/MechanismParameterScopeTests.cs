using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The scope owns every unmanaged byte for a single native call. Disposal must release all of it,
/// whatever order it was allocated in, so that no parameter object needs a lifetime of its own.
/// </summary>
/// <remarks>
/// Joins the serialized MemoryLeaks collection: two of these tests assert an exact
/// <see cref="UnmanagedMemory.OutstandingAllocationCount"/>, which is process-wide, so any test
/// class allocating concurrently perturbs the count. Every other class that reads that counter is
/// in this collection for the same reason.
/// </remarks>
[Collection("MemoryLeaks")]
public sealed class MechanismParameterScopeTests
{
    [Fact]
    public void Dispose_ReleasesEverythingAllocatedInTheScope()
    {
        int before = UnmanagedMemory.OutstandingAllocationCount;

        using (var scope = new MechanismParameterScope())
        {
            scope.Write([1, 2, 3, 4]);
            scope.Write([5, 6]);
            scope.WriteStruct(new CK_VERSION { Major = 3, Minor = 2 });
            Assert.True(UnmanagedMemory.OutstandingAllocationCount > before);
        }

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void Write_CopiesTheBytesAndReturnsAReadablePointer()
    {
        using var scope = new MechanismParameterScope();

        IntPtr p = scope.Write([0xDE, 0xAD, 0xBE, 0xEF]);

        Span<byte> read = stackalloc byte[4];
        UnmanagedMemory.Read(p, read);
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, read.ToArray());
    }

    [Fact]
    public void Write_EmptySpan_ReturnsZeroAndAllocatesNothing()
    {
        int before = UnmanagedMemory.OutstandingAllocationCount;
        using var scope = new MechanismParameterScope();

        Assert.Equal(IntPtr.Zero, scope.Write([]));
        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void WriteStructArray_LaysElementsOutContiguously()
    {
        using var scope = new MechanismParameterScope();
        CK_VERSION[] versions = [new() { Major = 1, Minor = 2 }, new() { Major = 3, Minor = 4 }];

        IntPtr p = scope.WriteStructArray<CK_VERSION>(versions);

        int size = UnmanagedMemory.SizeOf<CK_VERSION>();
        Assert.Equal(1, UnmanagedMemory.Read<CK_VERSION>(p).Major);
        Assert.Equal(3, UnmanagedMemory.Read<CK_VERSION>(p + size).Major);
    }

    // Sessions dispose the scope in a `finally` while some paths also dispose it on the way out, so a
    // second release has to be inert. It relied on not throwing, which asserted nothing explicitly:
    // the count assertions below are what distinguish "inert" from "freed the same block twice".
    [Fact]
    public void Dispose_IsIdempotent()
    {
        int before = UnmanagedMemory.OutstandingAllocationCount;
        var scope = new MechanismParameterScope();
        scope.Write([1]);
        Assert.True(UnmanagedMemory.OutstandingAllocationCount > before);

        scope.Dispose();
        int afterFirst = UnmanagedMemory.OutstandingAllocationCount;
        Assert.Equal(before, afterFirst);

        // UnmanagedMemory.Free throws on a pointer it no longer tracks, so a repeated release would
        // surface here rather than silently corrupting the heap.
        Assert.Null(Record.Exception(scope.Dispose));
        Assert.Equal(afterFirst, UnmanagedMemory.OutstandingAllocationCount);
    }
}
