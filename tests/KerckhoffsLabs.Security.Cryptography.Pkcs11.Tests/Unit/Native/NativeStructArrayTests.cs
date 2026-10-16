using System.Runtime.CompilerServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <see cref="NativeStructArray{T}"/> lays a template or list out in the layout the module reads. Both
/// layouts are plain bytes, so each is checked here on every OS, not only on the platform that uses it.
/// </summary>
public sealed unsafe class NativeStructArrayTests
{
    private static readonly CK_ATTRIBUTE[] Template =
    [
        new() { type = (NativeCULong)0x0000UL, value = (IntPtr)0x1000, valueLen = (NativeCULong)4UL },
        new() { type = (NativeCULong)0x0011UL, value = IntPtr.Zero, valueLen = (NativeCULong)0UL },
        new() { type = (NativeCULong)0x0161UL, value = (IntPtr)0x2000, valueLen = (NativeCULong)32UL },
    ];

    public static TheoryData<bool> Layouts => [false, true];

    // An empty template is passed as NULL with a count of 0, which is a legitimate Cryptoki argument.
    [Fact]
    public void EmptyTemplate_IsNull()
    {
        using var block = new NativeStructArray<CK_ATTRIBUTE>([], nullWhenEmpty: true);

        Assert.Equal(IntPtr.Zero, (IntPtr)block.Pointer);
        Assert.Equal(0UL, (ulong)block.Count);
    }

    // An empty list the module fills is a real address: NULL would ask for the count instead.
    [Fact]
    public void EmptyList_IsARealAddress()
    {
        using var block = new NativeStructArray<CK_INTERFACE>([], nullWhenEmpty: false);

        Assert.NotEqual(IntPtr.Zero, (IntPtr)block.Pointer);
        Assert.Equal(0UL, (ulong)block.Count);
    }

    [Theory]
    [MemberData(nameof(Layouts))]
    public void EachAttribute_IsLaidOutInOrder_AtTheLayoutsStride(bool windowsLayout)
    {
        using var block = new NativeStructArray<CK_ATTRIBUTE>(Template, nullWhenEmpty: true, windowsLayout);
        int stride = Pkcs11Marshal.SizeOf<CK_ATTRIBUTE>(windowsLayout);

        Assert.Equal((ulong)Template.Length, (ulong)block.Count);
        for (int i = 0; i < Template.Length; i++)
        {
            byte* entry = (byte*)block.Pointer + i * stride;
            CK_ATTRIBUTE laidOut = windowsLayout
                ? Unsafe.ReadUnaligned<CK_ATTRIBUTE_Windows>(entry).ToUnified()
                : Unsafe.ReadUnaligned<CK_ATTRIBUTE>(entry);
            AssertSame(Template[i], laidOut);
        }
    }

    // What the module writes into the block (here, each value's length) comes back to the caller.
    [Theory]
    [MemberData(nameof(Layouts))]
    public void CopyTo_ReturnsWhatTheModuleWrote(bool windowsLayout)
    {
        using var block = new NativeStructArray<CK_ATTRIBUTE>(Template, nullWhenEmpty: true, windowsLayout);
        int stride = Pkcs11Marshal.SizeOf<CK_ATTRIBUTE>(windowsLayout);
        for (int i = 0; i < Template.Length; i++)
        {
            IntPtr entry = (IntPtr)((byte*)block.Pointer + i * stride);
            CK_ATTRIBUTE written = Template[i];
            written.valueLen = (NativeCULong)(ulong)(100 + i);
            Pkcs11Marshal.WriteStructure(entry, in written, windowsLayout);
        }

        var back = new CK_ATTRIBUTE[Template.Length];
        block.CopyTo(back);

        for (int i = 0; i < Template.Length; i++)
        {
            Assert.Equal(Template[i].type, back[i].type);
            Assert.Equal(Template[i].value, back[i].value);
            Assert.Equal((ulong)(100 + i), (ulong)back[i].valueLen);
        }
    }

    // The common template fits the caller's stack buffer: laid out there, with no native allocation.
    [Theory]
    [MemberData(nameof(Layouts))]
    public void ArrayThatFitsTheStackBuffer_IsLaidOutThere_WithoutAllocating(bool windowsLayout)
    {
        Span<byte> stack = stackalloc byte[NativeStructArray.StackBytes];
        int before = UnmanagedMemory.ThreadAllocationCount;

        using (var block = new NativeStructArray<CK_ATTRIBUTE>(Template, nullWhenEmpty: true, windowsLayout, stack))
        {
            Assert.Equal((IntPtr)Unsafe.AsPointer(ref stack[0]), (IntPtr)block.Pointer);
            CK_ATTRIBUTE[] back = new CK_ATTRIBUTE[Template.Length];
            block.CopyTo(back);
            for (int i = 0; i < Template.Length; i++)
                AssertSame(Template[i], back[i]);
        }

        Assert.Equal(before, UnmanagedMemory.ThreadAllocationCount);
    }

    // A template too large for the stack buffer goes to the native heap, and is freed again.
    [Fact]
    public void ArrayLargerThanTheStackBuffer_GoesToTheHeap()
    {
        int fits = NativeStructArray.StackBytes / Pkcs11Marshal.SizeOf<CK_ATTRIBUTE>();
        CK_ATTRIBUTE[] large = [.. Enumerable.Range(0, fits + 1).Select(i => new CK_ATTRIBUTE { type = (NativeCULong)(ulong)i })];
        Span<byte> stack = stackalloc byte[NativeStructArray.StackBytes];
        int before = UnmanagedMemory.ThreadAllocationCount;

        using var block = new NativeStructArray<CK_ATTRIBUTE>(large, nullWhenEmpty: true, stack);

        Assert.Equal(before + 1, UnmanagedMemory.ThreadAllocationCount);
        Assert.NotEqual((IntPtr)Unsafe.AsPointer(ref stack[0]), (IntPtr)block.Pointer);
        CK_ATTRIBUTE[] back = new CK_ATTRIBUTE[large.Length];
        block.CopyTo(back);
        Assert.Equal(large.Select(a => (ulong)a.type), back.Select(a => (ulong)a.type));
    }

    // The stack block held the template's value pointers and lengths; it is wiped like a heap block.
    [Fact]
    public void StackBlock_IsZeroizedOnDispose()
    {
        Span<byte> stack = stackalloc byte[NativeStructArray.StackBytes];
        stack.Fill(0xEE);

        using (new NativeStructArray<CK_ATTRIBUTE>(Template, nullWhenEmpty: true, stack))
        {
        }

        Assert.All(stack[..(Template.Length * Pkcs11Marshal.SizeOf<CK_ATTRIBUTE>())].ToArray(), b => Assert.Equal(0, b));
    }

    private static void AssertSame(CK_ATTRIBUTE expected, CK_ATTRIBUTE actual)
    {
        Assert.Equal(expected.type, actual.type);
        Assert.Equal(expected.value, actual.value);
        Assert.Equal(expected.valueLen, actual.valueLen);
    }
}
