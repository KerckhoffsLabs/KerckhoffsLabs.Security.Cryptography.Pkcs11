using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

// In the MemoryLeaks collection so it serializes with the allocation-sensitive tests (the leak
// snapshots and DebugModeEnabled static state). CK_VERSION is a plain (non-[PackedForPkcs11])
// blittable struct; CK_MECHANISM_INFO is [PackedForPkcs11] — together they cover both branches of
// the SizeOf/Write/Read overloads.
[Collection("MemoryLeaks")]
public sealed class UnmanagedMemoryTests
{
    private static void WithBuffer(int size, Action<IntPtr> body)
    {
        IntPtr p = UnmanagedMemory.Allocate(size);
        try { body(p); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    // === Allocate / Free =================================================

    [Fact]
    public void Allocate_NegativeSize_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => UnmanagedMemory.Allocate(-1));
        Assert.Equal("size", ex.ParamName);
    }

    [Fact]
    public void Allocate_ZeroFills() => WithBuffer(8, p => Assert.Equal(new byte[8], UnmanagedMemory.Read(p, 8)));

    [Fact]
    public void Allocate_Zero_IsTrackedAndFreeable()
    {
        // size == 0 skips the NativeMemory.Clear branch but is still tracked + freeable.
        IntPtr p = UnmanagedMemory.Allocate(0);
        UnmanagedMemory.Free(ref p);
        Assert.Equal(IntPtr.Zero, p);
    }

    [Fact]
    public void Free_NullPointer_IsNoOp()
    {
        IntPtr z = IntPtr.Zero;
        UnmanagedMemory.Free(ref z); // must not throw
        Assert.Equal(IntPtr.Zero, z);
    }

    [Fact]
    public void Free_UntrackedPointer_Throws()
    {
        // Never allocated through UnmanagedMemory -> rejected before any FreeHGlobal.
        IntPtr bogus = 0x1234;
        Assert.Throws<InvalidOperationException>(() => UnmanagedMemory.Free(ref bogus));
    }

    [Fact]
    public void Free_SetsPointerToZero()
    {
        IntPtr p = UnmanagedMemory.Allocate(8);
        UnmanagedMemory.Free(ref p);
        Assert.Equal(IntPtr.Zero, p);
    }

    // === Write/Read — byte[] =============================================

    [Fact]
    public void WriteRead_ByteArray_RoundTrips()
    {
        WithBuffer(4, p =>
        {
            UnmanagedMemory.Write(p, [1, 2, 3, 4]);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, UnmanagedMemory.Read(p, 4));
        });
    }

    [Fact]
    public void Write_ByteArray_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, new byte[1]));

    [Fact]
    public void Write_ByteArray_NullContent_Throws() =>
        WithBuffer(4, p => Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(p, (byte[])null!)));

    // === Write/Read — span ===============================================

    [Fact]
    public void WriteRead_Span_RoundTrips()
    {
        WithBuffer(4, p =>
        {
            UnmanagedMemory.Write(p, [5, 6, 7, 8]);
            byte[] dst = new byte[4];
            UnmanagedMemory.Read(p, dst.AsSpan());
            Assert.Equal(new byte[] { 5, 6, 7, 8 }, dst);
        });
    }

    [Fact]
    public void Write_Span_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, new byte[1].AsSpan()));

    [Fact]
    public void Read_Span_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, new byte[1].AsSpan()));

    // === Read — int / byte[] dest ========================================

    [Fact]
    public void Read_Int_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, 4));

    [Fact]
    public void Read_Int_NegativeSize_Throws()
    {
        WithBuffer(4, p =>
        {
            var ex = Assert.Throws<ArgumentException>(() => UnmanagedMemory.Read(p, -1));
            Assert.Equal("size", ex.ParamName);
        });
    }

    [Fact]
    public void Read_ByteArrayDest_RoundTrips()
    {
        WithBuffer(4, p =>
        {
            UnmanagedMemory.Write(p, [9, 8, 7, 6]);
            byte[] dst = new byte[4];
            UnmanagedMemory.Read(p, dst);
            Assert.Equal(new byte[] { 9, 8, 7, 6 }, dst);
        });
    }

    [Fact]
    public void Read_ByteArrayDest_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, new byte[1]));

    // === SizeOf ==========================================================

    [Fact]
    public void SizeOf_Generic_NonPacked_UsesMarshalSizeOf() =>
        Assert.Equal(2, UnmanagedMemory.SizeOf<CK_VERSION>()); // Major + Minor

    [Fact]
    public void SizeOf_Generic_Packed_UsesPackedSize() =>
        Assert.Equal(3 * UnmanagedMemory.NativeULongSize, UnmanagedMemory.SizeOf<CK_MECHANISM_INFO>());

    // === Write<T> / Read<T> ==============================================

    [Fact]
    public void WriteRead_Generic_NonPacked_RoundTrips()
    {
        WithBuffer(UnmanagedMemory.SizeOf<CK_VERSION>(), p =>
        {
            var v = new CK_VERSION { Major = 3, Minor = 40 };
            UnmanagedMemory.Write(p, in v);
            var back = UnmanagedMemory.Read<CK_VERSION>(p);
            Assert.Equal((byte)3, back.Major);
            Assert.Equal((byte)40, back.Minor);
        });
    }

    [Fact]
    public void WriteRead_Generic_Packed_RoundTrips()
    {
        WithBuffer(UnmanagedMemory.SizeOf<CK_MECHANISM_INFO>(), p =>
        {
            var m = new CK_MECHANISM_INFO
            {
                MinKeySize = (NativeCULong)128UL,
                MaxKeySize = (NativeCULong)256UL,
                Flags = (NativeCULong)4UL,
            };
            UnmanagedMemory.Write(p, in m);
            var back = UnmanagedMemory.Read<CK_MECHANISM_INFO>(p);
            Assert.Equal(128UL, (ulong)back.MinKeySize);
            Assert.Equal(256UL, (ulong)back.MaxKeySize);
            Assert.Equal(4UL, (ulong)back.Flags);
        });
    }

    [Fact]
    public void Write_Generic_NullMemory_Throws()
    {
        var v = new CK_VERSION();
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, in v));
    }

    [Fact]
    public void Read_Generic_NullMemory_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read<CK_VERSION>(IntPtr.Zero));

    // === Zeroize ==========================================================

    [Fact]
    public void Free_ZeroesBufferBeforeRelease()
    {
        // Allocate, fill, free; the Free path zeroes before FreeHGlobal. We can't read freed memory
        // safely, so just assert the round-trip + that Free succeeds (Zeroize is exercised on the way out).
        IntPtr p = UnmanagedMemory.Allocate(4);
        UnmanagedMemory.Write(p, [0xFF, 0xFF, 0xFF, 0xFF]);
        Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, UnmanagedMemory.Read(p, 4));
        UnmanagedMemory.Free(ref p);
        Assert.Equal(IntPtr.Zero, p);
    }
}
