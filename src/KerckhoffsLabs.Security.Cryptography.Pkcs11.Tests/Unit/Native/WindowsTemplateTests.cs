using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The attribute template a wrapper hands a module on Windows is rewritten into the Pack=1
/// <see cref="CK_ATTRIBUTE_Windows"/> layout first. The conversion is pure, so it is checked here on every OS,
/// not only on the Windows legs where it is called.
/// </summary>
public sealed class WindowsTemplateTests
{
    // An empty template is passed as NULL, which is a legitimate Cryptoki argument.
    [Fact]
    public void EmptyTemplate_BecomesNull()
        => Assert.Null(LowLevelPkcs11Library.ToWindowsTemplate([]));

    [Fact]
    public void EachAttribute_IsCopiedInOrder()
    {
        CK_ATTRIBUTE[] template =
        [
            new() { type = (NativeCULong)0x0000UL, value = (IntPtr)0x1000, valueLen = (NativeCULong)4UL },
            new() { type = (NativeCULong)0x0011UL, value = IntPtr.Zero, valueLen = (NativeCULong)0UL },
            new() { type = (NativeCULong)0x0161UL, value = (IntPtr)0x2000, valueLen = (NativeCULong)32UL },
        ];

        CK_ATTRIBUTE_Windows[] packed = Assert.IsType<CK_ATTRIBUTE_Windows[]>(LowLevelPkcs11Library.ToWindowsTemplate(template));

        Assert.Equal(template.Length, packed.Length);
        for (int i = 0; i < template.Length; i++)
        {
            CK_ATTRIBUTE back = packed[i].ToUnified();
            Assert.Equal(template[i].type, back.type);
            Assert.Equal(template[i].value, back.value);
            Assert.Equal(template[i].valueLen, back.valueLen);
        }
    }
}
