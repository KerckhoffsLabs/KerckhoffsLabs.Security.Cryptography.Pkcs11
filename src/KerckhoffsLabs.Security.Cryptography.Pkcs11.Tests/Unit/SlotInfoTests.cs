using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SlotInfoTests
{
    [Fact]
    public void Decodes_AllFields()
    {
        var native = new CK_SLOT_INFO();
        NativeTestStructs.FillPadded(native.SlotDescription, "USB Reader Slot 0");
        NativeTestStructs.FillPadded(native.ManufacturerId, "Acme Corp");
        native.Flags = (NativeCULong)(CKF.CKF_TOKEN_PRESENT.Value | CKF.CKF_HW_SLOT.Value);
        native.HardwareVersion = new CK_VERSION { Major = 1, Minor = 0 };
        native.FirmwareVersion = new CK_VERSION { Major = 2, Minor = 5 };

        var info = new SlotInfo((NativeCULong)9UL, native);

        Assert.Equal(9UL, info.SlotId.Value);
        Assert.Equal("USB Reader Slot 0", info.SlotDescription);
        Assert.Equal("Acme Corp", info.ManufacturerId);
        Assert.Equal("1.0", info.HardwareVersion);   // minor 0 -> "M.0"
        Assert.Equal("2.05", info.FirmwareVersion);  // minor as hundredths
        Assert.True(info.SlotFlags.TokenPresent);
        Assert.True(info.SlotFlags.HardwareSlot);
        Assert.False(info.SlotFlags.RemovableDevice);
    }

    [Fact]
    public void Strings_TrailingSpacePaddingIsTrimmed()
    {
        var native = new CK_SLOT_INFO();
        NativeTestStructs.FillPadded(native.SlotDescription, "slot"); // remaining bytes are spaces
        var info = new SlotInfo((NativeCULong)0UL, native);
        Assert.Equal("slot", info.SlotDescription);
    }

    [Theory]
    [InlineData(3, 0, "3.0")]      // minor 0 -> "M.0"
    [InlineData(3, 7, "3.07")]     // 1..99 -> zero-padded hundredths
    [InlineData(3, 99, "3.99")]    // upper bound of the hundredths range
    [InlineData(3, 200, "Invalid version")] // > 99 (0x63) -> invalid
    public void Version_RendersPerCkVersionRules(byte major, byte minor, string expected)
    {
        var native = new CK_SLOT_INFO { HardwareVersion = new CK_VERSION { Major = major, Minor = minor } };
        var info = new SlotInfo((NativeCULong)0UL, native);
        Assert.Equal(expected, info.HardwareVersion);
    }
}
