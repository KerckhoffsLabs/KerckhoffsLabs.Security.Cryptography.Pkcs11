using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Hermetic coverage for <see cref="UnmanagedMemory"/>: the allocate/free tracker and its guards,
/// the byte[]/span/struct read-write round-trips, the null-pointer and unsupported-type guards on
/// every overload, the debug-log toggle, and the packed vs. non-packed marshalling dispatch.
/// (The Windows-packed sibling branches are covered on the Windows CI legs.)
/// </summary>
public sealed class UnmanagedMemoryTests
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Blittable
    {
        public int A;
        public long B;
    }

    // === Allocate / Free tracker ============================================

    [Fact]
    public void Allocate_Negative_Throws() =>
        Assert.Throws<ArgumentException>(() => UnmanagedMemory.Allocate(-1));

    [Fact]
    public void Allocate_ZeroFills_AndTracks()
    {
        IntPtr p = UnmanagedMemory.Allocate(8);
        try
        {
            // The tracker is process-wide and other test classes allocate/free in parallel, so we
            // can only assert that our live allocation is counted (>= 1), never an exact delta.
            Assert.True(UnmanagedMemory.OutstandingAllocationCount >= 1);
            Assert.Equal(new byte[8], UnmanagedMemory.Read(p, 8)); // zero-filled
        }
        finally { UnmanagedMemory.Free(ref p); }

        Assert.Equal(IntPtr.Zero, p); // Free nulls the ref
    }

    [Fact]
    public void Free_ZeroPointer_IsNoOp()
    {
        IntPtr p = IntPtr.Zero;
        Assert.Null(Record.Exception(() => UnmanagedMemory.Free(ref p)));
    }

    [Fact]
    public void Free_Untracked_Throws()
    {
        // A non-zero pointer the tracker never handed out — rejected before any FreeHGlobal.
        IntPtr bogus = 0x1234;
        Assert.Throws<InvalidOperationException>(() => UnmanagedMemory.Free(ref bogus));
    }

    [Fact]
    public void DebugMode_Toggle_TracksAllocateAndFree()
    {
        bool prev = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
        try
        {
            Assert.True(UnmanagedMemory.DebugModeEnabled);
            IntPtr p = UnmanagedMemory.Allocate(16); // exercises the debug-log branch
            Assert.True(UnmanagedMemory.OutstandingAllocationCount >= 1); // process-wide; no exact delta
            UnmanagedMemory.Free(ref p);             // exercises the debug-log branch
            Assert.Equal(IntPtr.Zero, p);
        }
        finally { UnmanagedMemory.DebugModeEnabled = prev; }
    }

    // === Write / Read: byte[] and spans =====================================

    [Fact]
    public void WriteRead_ByteArray_RoundTrips()
    {
        IntPtr p = UnmanagedMemory.Allocate(4);
        try
        {
            UnmanagedMemory.Write(p, new byte[] { 1, 2, 3, 4 });
            Assert.Equal([1, 2, 3, 4], UnmanagedMemory.Read(p, 4));

            byte[] into = new byte[4];
            UnmanagedMemory.Read(p, into);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, into);

            Span<byte> span = stackalloc byte[4];
            UnmanagedMemory.Read(p, span);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, span.ToArray());
        }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void WriteSpan_RoundTrips()
    {
        IntPtr p = UnmanagedMemory.Allocate(3);
        try
        {
            UnmanagedMemory.Write(p, (ReadOnlySpan<byte>)new byte[] { 7, 8, 9 });
            Assert.Equal([7, 8, 9], UnmanagedMemory.Read(p, 3));
        }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void Write_NullPointer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, (ReadOnlySpan<byte>)new byte[1]));
    }

    [Fact]
    public void Write_NullContent_Throws()
    {
        IntPtr p = UnmanagedMemory.Allocate(1);
        try { Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(p, (byte[])null!)); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void Read_NullPointer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, 4));
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, new byte[4]));
        Assert.Throws<ArgumentNullException>(() =>
        {
            Span<byte> s = stackalloc byte[4];
            UnmanagedMemory.Read(IntPtr.Zero, s);
        });
    }

    [Fact]
    public void Read_NegativeSize_Throws()
    {
        IntPtr p = UnmanagedMemory.Allocate(1);
        try { Assert.Throws<ArgumentException>(() => UnmanagedMemory.Read(p, -1)); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    // === Struct marshalling: non-packed (Marshal) path ======================

    [Fact]
    public void WriteReadStruct_NonPacked_RoundTrips()
    {
        IntPtr p = UnmanagedMemory.Allocate(UnmanagedMemory.SizeOf<Blittable>());
        try
        {
            UnmanagedMemory.Write(p, new Blittable { A = 42, B = 9_000_000_000L });
            Blittable read = UnmanagedMemory.Read<Blittable>(p);
            Assert.Equal(42, read.A);
            Assert.Equal(9_000_000_000L, read.B);
        }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void WriteGeneric_NullPointer_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, new Blittable()));

    [Fact]
    public void ReadGeneric_NullPointer_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read<Blittable>(IntPtr.Zero));

    // === SizeOf =============================================================

    [Fact]
    public void SizeOf_Generic_NonPacked_MatchesMarshal() =>
        Assert.Equal(Marshal.SizeOf<Blittable>(), UnmanagedMemory.SizeOf<Blittable>());

    [Fact]
    public void SizeOf_Type_NonPacked_Throws() =>
        Assert.Throws<NotSupportedException>(() => UnmanagedMemory.SizeOf(typeof(Blittable)));

    [Fact]
    public void SizeOf_Type_Null_Throws() =>
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.SizeOf(null!));

    [Fact]
    public void SizeOf_Type_Packed_ReturnsPositive() =>
        Assert.True(UnmanagedMemory.SizeOf(typeof(CK_RSA_PKCS_PSS_PARAMS)) > 0);

    // === Object/Type overloads: packed dispatch + guards ====================

    [Fact]
    public void WriteObject_ReadType_Packed_RoundTrips()
    {
        IntPtr p = UnmanagedMemory.Allocate(UnmanagedMemory.SizeOf(typeof(CK_RSA_PKCS_PSS_PARAMS)));
        try
        {
            var value = new CK_RSA_PKCS_PSS_PARAMS
            {
                HashAlg = (NativeCULong)1,
                Mgf = (NativeCULong)2,
                Len = (NativeCULong)32,
            };
            UnmanagedMemory.Write(p, (object)value);

            var read = (CK_RSA_PKCS_PSS_PARAMS)UnmanagedMemory.Read(p, typeof(CK_RSA_PKCS_PSS_PARAMS))!;
            Assert.Equal(1UL, (ulong)read.HashAlg);
            Assert.Equal(2UL, (ulong)read.Mgf);
            Assert.Equal(32UL, (ulong)read.Len);
        }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void WriteObject_NonPacked_Throws()
    {
        IntPtr p = UnmanagedMemory.Allocate(8);
        try { Assert.Throws<NotSupportedException>(() => UnmanagedMemory.Write(p, (object)new Blittable())); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void WriteObject_NullArgs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(IntPtr.Zero, (object)new Blittable()));
        IntPtr p = UnmanagedMemory.Allocate(8);
        try { Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Write(p, (object)null!)); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void ReadType_NonPacked_Throws()
    {
        IntPtr p = UnmanagedMemory.Allocate(8);
        try { Assert.Throws<NotSupportedException>(() => UnmanagedMemory.Read(p, typeof(Blittable))); }
        finally { UnmanagedMemory.Free(ref p); }
    }

    [Fact]
    public void ReadType_NullArgs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(IntPtr.Zero, typeof(CK_RSA_PKCS_PSS_PARAMS)));
        IntPtr p = UnmanagedMemory.Allocate(8);
        try { Assert.Throws<ArgumentNullException>(() => UnmanagedMemory.Read(p, (Type)null!)); }
        finally { UnmanagedMemory.Free(ref p); }
    }
}
