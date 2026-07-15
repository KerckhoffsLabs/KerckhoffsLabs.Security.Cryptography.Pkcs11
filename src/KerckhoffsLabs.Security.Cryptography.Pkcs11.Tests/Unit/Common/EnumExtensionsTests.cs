using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// Round-trip and validation tests for the per-enum extension methods. One representative
/// sample per enum keeps the test count reasonable; the extension implementations are
/// mechanically identical across enums. <c>ToCK*</c> validates for caller-supplied values —
/// EXCEPT <c>ToCKR</c> and <c>ToCKM</c>, which convert module-controlled values where
/// vendor-defined and newer-than-this-enum codes are spec-legal and must round-trip
/// unvalidated.
/// </summary>
public sealed class EnumExtensionsTests
{
    [Fact] public void CKR_RoundTrip() { CKR v = CKR.CKR_OK; Assert.Equal(v, v.ToCULong().ToCKR()); }
    [Fact] public void CKM_RoundTrip() { CKM v = CKM.CKM_AES_GCM; Assert.Equal(v, v.ToCULong().ToCKM()); }
    [Fact] public void CKA_RoundTrip() { CKA v = CKA.CKA_CLASS; Assert.Equal(v, v.ToCULong().ToCKA()); }
    [Fact] public void CKC_RoundTrip() { CKC v = CKC.CKC_X_509; Assert.Equal(v, v.ToCULong().ToCKC()); }
    [Fact] public void CKD_RoundTrip() { CKD v = CKD.CKD_NULL; Assert.Equal(v, v.ToCULong().ToCKD()); }
    [Fact] public void CKG_RoundTrip() { CKG v = CKG.CKG_MGF1_SHA256; Assert.Equal(v, v.ToCULong().ToCKG()); }
    [Fact] public void CKH_RoundTrip() { CKH v = CKH.CKH_MONOTONIC_COUNTER; Assert.Equal(v, v.ToCULong().ToCKH()); }
    [Fact] public void CKK_RoundTrip() { CKK v = CKK.CKK_AES; Assert.Equal(v, v.ToCULong().ToCKK()); }
    [Fact] public void CKN_RoundTrip() { CKN v = CKN.CKN_SURRENDER; Assert.Equal(v, v.ToCULong().ToCKN()); }
    [Fact] public void CKO_RoundTrip() { CKO v = CKO.CKO_PRIVATE_KEY; Assert.Equal(v, v.ToCULong().ToCKO()); }
    [Fact] public void CKP_RoundTrip() { CKP v = CKP.CKP_PKCS5_PBKD2_HMAC_SHA1; Assert.Equal(v, v.ToCULong().ToCKP()); }
    [Fact] public void CKS_RoundTrip() { CKS v = CKS.CKS_RO_PUBLIC_SESSION; Assert.Equal(v, v.ToCULong().ToCKS()); }
    [Fact] public void CKU_RoundTrip() { CKU v = CKU.CKU_USER; Assert.Equal(v, v.ToCULong().ToCKU()); }

    // ToCKR / ToCKM convert module-controlled values: vendor-defined codes (≥ CK*_VENDOR_DEFINED)
    // and codes newer than the enum are spec-legal, so they round-trip instead of throwing.
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

    [Fact]
    public void ToCK_ThrowsOnUndefinedValue()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKA());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKC());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKD());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKG());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKH());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKK());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKN());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKO());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKP());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKS());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKU());
    }

    // Exhaustive round-trips for the alias-free enums (every defined member must survive). CKM/CKK/CKA
    // are excluded: they intentionally carry duplicate-value spec aliases (e.g. CKK_EC == CKK_ECDSA),
    // so a numeric value can only map back to one member and exhaustive round-tripping can't hold.
    [Fact] public void CKR_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKR>(), v => Assert.Equal(v, v.ToCULong().ToCKR()));
    [Fact] public void CKU_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKU>(), v => Assert.Equal(v, v.ToCULong().ToCKU()));
    [Fact] public void CKS_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKS>(), v => Assert.Equal(v, v.ToCULong().ToCKS()));
    [Fact] public void CKO_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKO>(), v => Assert.Equal(v, v.ToCULong().ToCKO()));
    [Fact] public void CKC_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKC>(), v => Assert.Equal(v, v.ToCULong().ToCKC()));
    [Fact] public void CKD_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKD>(), v => Assert.Equal(v, v.ToCULong().ToCKD()));
    [Fact] public void CKG_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKG>(), v => Assert.Equal(v, v.ToCULong().ToCKG()));
    [Fact] public void CKH_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKH>(), v => Assert.Equal(v, v.ToCULong().ToCKH()));
    [Fact] public void CKN_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKN>(), v => Assert.Equal(v, v.ToCULong().ToCKN()));
    [Fact] public void CKP_AllMembersRoundTrip() => Assert.All(Enum.GetValues<CKP>(), v => Assert.Equal(v, v.ToCULong().ToCKP()));
}
