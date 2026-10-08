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

    private static void AssertSame(CK_ATTRIBUTE expected, CK_ATTRIBUTE actual)
    {
        Assert.Equal(expected.type, actual.type);
        Assert.Equal(expected.value, actual.value);
        Assert.Equal(expected.valueLen, actual.valueLen);
    }
}
