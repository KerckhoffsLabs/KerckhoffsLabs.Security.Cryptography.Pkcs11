using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Pure marshalling/decoding logic — no token needed. Builds CK_TOKEN_INFO native structs and
// asserts how TokenInfo decodes them.
public sealed class TokenInfoTests
{
    private static CK_TOKEN_INFO Sample()
    {
        var info = new CK_TOKEN_INFO();
        NativeTestStructs.FillPadded(info.Label, "My Token");
        NativeTestStructs.FillPadded(info.ManufacturerId, "Acme Corp");
        NativeTestStructs.FillPadded(info.Model, "Model-X");
        NativeTestStructs.FillPadded(info.SerialNumber, "SN12345");
        info.Flags = (NativeCULong)(CKF.CKF_RNG | CKF.CKF_LOGIN_REQUIRED);
        info.MaxSessionCount = (NativeCULong)10UL;
        info.SessionCount = (NativeCULong)3UL;
        info.MaxRwSessionCount = (NativeCULong)8UL;
        info.RwSessionCount = (NativeCULong)2UL;
        info.MaxPinLen = (NativeCULong)32UL;
        info.MinPinLen = (NativeCULong)4UL;
        info.TotalPublicMemory = (NativeCULong)100000UL;
        info.FreePublicMemory = (NativeCULong)90000UL;
        info.TotalPrivateMemory = (NativeCULong)50000UL;
        info.FreePrivateMemory = (NativeCULong)40000UL;
        info.HardwareVersion = new CK_VERSION { Major = 2, Minor = 1 };  // minor renders as hundredths
        info.FirmwareVersion = new CK_VERSION { Major = 3, Minor = 40 };
        NativeTestStructs.FillPadded(info.UtcTime, "2024011510304500");
        return info;
    }

    [Fact]
    public void Decodes_AllScalarFields()
    {
        var info = new TokenInfo((NativeCULong)7UL, Sample());

        Assert.Equal(7UL, info.SlotId.Value);
        Assert.Equal("My Token", info.Label);
        Assert.Equal("Acme Corp", info.ManufacturerId);
        Assert.Equal("Model-X", info.Model);
        Assert.Equal("SN12345", info.SerialNumber);
        Assert.Equal(10UL, info.MaxSessionCount);
        Assert.Equal(3UL, info.SessionCount);
        Assert.Equal(8UL, info.MaxRwSessionCount);
        Assert.Equal(2UL, info.RwSessionCount);
        Assert.Equal(32UL, info.MaxPinLen);
        Assert.Equal(4UL, info.MinPinLen);
        Assert.Equal(100000UL, info.TotalPublicMemory);
        Assert.Equal(90000UL, info.FreePublicMemory);
        Assert.Equal(50000UL, info.TotalPrivateMemory);
        Assert.Equal(40000UL, info.FreePrivateMemory);
        Assert.Equal(new Version(2, 1), info.HardwareVersion);
        Assert.Equal(new Version(3, 40), info.FirmwareVersion);
    }

    [Fact]
    public void TokenFlags_AreWiredFromFlagsField()
    {
        var info = new TokenInfo((NativeCULong)0UL, Sample());
        Assert.True(info.TokenFlags.Rng);
        Assert.True(info.TokenFlags.LoginRequired);
        Assert.False(info.TokenFlags.WriteProtected);
    }

    [Fact]
    public void Strings_TrailingSpacePaddingIsTrimmed()
    {
        var native = new CK_TOKEN_INFO();
        NativeTestStructs.FillPadded(native.Label, "abc"); // remaining 29 bytes are spaces
        var info = new TokenInfo((NativeCULong)0UL, native);
        Assert.Equal("abc", info.Label);
    }

    [Fact]
    public void Strings_DecodeUtf8MultiByte()
    {
        var native = new CK_TOKEN_INFO();
        NativeTestStructs.FillPadded(native.Label, "Tökén café"); // multi-byte UTF-8
        var info = new TokenInfo((NativeCULong)0UL, native);
        Assert.Equal("Tökén café", info.Label);
    }

    [Fact]
    public void UtcTime_ValidString_ParsesToUtcDateTime()
    {
        var info = new TokenInfo((NativeCULong)0UL, Sample());

        Assert.Equal("2024011510304500", info.UtcTimeString);
        Assert.NotNull(info.UtcTime);
        Assert.Equal(new DateTime(2024, 1, 15, 10, 30, 45, DateTimeKind.Utc), info.UtcTime!.Value);
        Assert.Equal(DateTimeKind.Utc, info.UtcTime!.Value.Kind);
    }

    [Fact]
    public void UtcTime_InvalidString_IsNullButStringPreserved()
    {
        var native = Sample();
        NativeTestStructs.FillPadded(native.UtcTime, "not-a-timestamp!"); // 16 bytes, unparseable
        var info = new TokenInfo((NativeCULong)0UL, native);

        Assert.Equal("not-a-timestamp!", info.UtcTimeString);
        Assert.Null(info.UtcTime);
    }

    [Fact]
    public void UtcTime_BlankClocklessToken_IsNull()
    {
        var native = Sample();
        NativeTestStructs.FillPadded(native.UtcTime, ""); // all spaces -> trims to empty
        var info = new TokenInfo((NativeCULong)0UL, native);

        Assert.Equal("", info.UtcTimeString);
        Assert.Null(info.UtcTime);
    }
}
