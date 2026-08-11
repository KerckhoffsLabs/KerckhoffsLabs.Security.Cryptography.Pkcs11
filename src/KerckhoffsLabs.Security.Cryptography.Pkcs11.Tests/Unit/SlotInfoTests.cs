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
        native.Flags = (NativeCULong)(CKF.CKF_TOKEN_PRESENT | CKF.CKF_HW_SLOT);
        native.HardwareVersion = new CK_VERSION { Major = 1, Minor = 0 };
        native.FirmwareVersion = new CK_VERSION { Major = 2, Minor = 5 };

        var info = new SlotInfo((NativeCULong)9UL, native);

        Assert.Equal(9UL, info.SlotId.Value);
        Assert.Equal("USB Reader Slot 0", info.SlotDescription);
        Assert.Equal("Acme Corp", info.ManufacturerId);
        Assert.Equal(new Version(1, 0), info.HardwareVersion);
        Assert.Equal(new Version(2, 5), info.FirmwareVersion);
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

    // The two CK_VERSION bytes reach the caller verbatim, including minor values above the
    // hundredths range that a real module (NSS softoken reports 3.125) actually emits.
    [Theory]
    [InlineData(3, 0)]
    [InlineData(3, 7)]
    [InlineData(3, 99)]   // upper bound of the hundredths range
    [InlineData(3, 125)]  // beyond it, and still not a sentinel
    [InlineData(3, 200)]
    public void Version_CarriesTheRawCkVersionFields(byte major, byte minor)
    {
        var native = new CK_SLOT_INFO { HardwareVersion = new CK_VERSION { Major = major, Minor = minor } };
        var info = new SlotInfo((NativeCULong)0UL, native);

        Assert.Equal(new Version(major, minor), info.HardwareVersion);
        Assert.Equal(-1, info.HardwareVersion.Build);  // CK_VERSION has no third field to invent
    }
}
