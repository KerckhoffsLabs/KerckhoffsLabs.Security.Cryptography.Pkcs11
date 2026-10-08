using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Round-trip tests for <c>ToCKR</c> and <c>ToCKM</c>, the conversions of module-controlled values.
/// Vendor-defined and newer-than-this-enum codes are spec-legal there, so they must round-trip
/// unvalidated.
/// </summary>
public sealed class EnumExtensionsTests
{
    [Fact] public void CKR_RoundTrip() { CKR v = CKR.CKR_OK; Assert.Equal(v, v.ToCULong().ToCKR()); }
    [Fact] public void CKM_RoundTrip() { CKM v = CKM.CKM_AES_GCM; Assert.Equal(v, v.ToCULong().ToCKM()); }

    // Vendor-defined codes (≥ CK*_VENDOR_DEFINED) and codes newer than the enum round-trip instead
    // of throwing.
    [Theory]
    [InlineData(0x80000000u)] // exactly CKR_VENDOR_DEFINED / CKM_VENDOR_DEFINED
    [InlineData(0x80000123u)] // a typical vendor code
    [InlineData(0x0000FFFFu)] // unknown non-vendor value (e.g. a future spec code)
    public void ToCKR_ToCKM_PassUndefinedValuesThrough(uint raw)
    {
        NativeCULong value = (NativeCULong)raw;
        Assert.Equal(raw, (uint)value.ToCKR());
        Assert.Equal(raw, (uint)value.ToCKM());
    }

    // CKR has no duplicate-value aliases, so every defined member must survive the round trip.
    [Fact] public void CKR_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKR>(), v => Assert.Equal(v, v.ToCULong().ToCKR()));
}
