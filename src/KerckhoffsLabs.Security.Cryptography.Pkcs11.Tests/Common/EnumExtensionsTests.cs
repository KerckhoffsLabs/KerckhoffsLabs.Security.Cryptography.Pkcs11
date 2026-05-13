using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Common;

/// <summary>
/// Round-trip and *Checked-failure tests for the per-enum extension methods.
/// One representative sample per enum keeps the test count reasonable; the
/// extension implementations are mechanically identical across enums.
/// </summary>
public class EnumExtensionsTests
{
    [Fact] public void CKR_RoundTrip()  { CKR v = CKR.CKR_OK;                    Assert.Equal(v, v.ToCULong().ToCKR());  Assert.Equal(v, v.ToCULong().ToCKRChecked()); }
    [Fact] public void CKM_RoundTrip()  { CKM v = CKM.CKM_AES_GCM;               Assert.Equal(v, v.ToCULong().ToCKM());  Assert.Equal(v, v.ToCULong().ToCKMChecked()); }
    [Fact] public void CKA_RoundTrip()  { CKA v = CKA.CKA_CLASS;                 Assert.Equal(v, v.ToCULong().ToCKA());  Assert.Equal(v, v.ToCULong().ToCKAChecked()); }
    [Fact] public void CKC_RoundTrip()  { CKC v = CKC.CKC_X_509;                 Assert.Equal(v, v.ToCULong().ToCKC());  Assert.Equal(v, v.ToCULong().ToCKCChecked()); }
    [Fact] public void CKD_RoundTrip()  { CKD v = CKD.CKD_NULL;                  Assert.Equal(v, v.ToCULong().ToCKD());  Assert.Equal(v, v.ToCULong().ToCKDChecked()); }
    [Fact] public void CKG_RoundTrip()  { CKG v = CKG.CKG_MGF1_SHA256;           Assert.Equal(v, v.ToCULong().ToCKG());  Assert.Equal(v, v.ToCULong().ToCKGChecked()); }
    [Fact] public void CKH_RoundTrip()  { CKH v = CKH.CKH_MONOTONIC_COUNTER;     Assert.Equal(v, v.ToCULong().ToCKH()); Assert.Equal(v, v.ToCULong().ToCKHChecked()); }
    [Fact] public void CKK_RoundTrip()  { CKK v = CKK.CKK_AES;                   Assert.Equal(v, v.ToCULong().ToCKK());  Assert.Equal(v, v.ToCULong().ToCKKChecked()); }
    [Fact] public void CKN_RoundTrip()  { CKN v = CKN.CKN_SURRENDER;             Assert.Equal(v, v.ToCULong().ToCKN());  Assert.Equal(v, v.ToCULong().ToCKNChecked()); }
    [Fact] public void CKO_RoundTrip()  { CKO v = CKO.CKO_PRIVATE_KEY;           Assert.Equal(v, v.ToCULong().ToCKO());  Assert.Equal(v, v.ToCULong().ToCKOChecked()); }
    [Fact] public void CKP_RoundTrip()  { CKP v = CKP.CKP_PKCS5_PBKD2_HMAC_SHA1; Assert.Equal(v, v.ToCULong().ToCKP()); Assert.Equal(v, v.ToCULong().ToCKPChecked()); }
    [Fact] public void CKS_RoundTrip()  { CKS v = CKS.CKS_RO_PUBLIC_SESSION;     Assert.Equal(v, v.ToCULong().ToCKS()); Assert.Equal(v, v.ToCULong().ToCKSChecked()); }
    [Fact] public void CKU_RoundTrip()  { CKU v = CKU.CKU_USER;                  Assert.Equal(v, v.ToCULong().ToCKU());  Assert.Equal(v, v.ToCULong().ToCKUChecked()); }

    [Fact]
    public void Checked_ThrowsOnUndefinedValue()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKRChecked());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKAChecked());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKMChecked());
    }

    [Fact]
    public void Loose_CastsThroughWithoutValidation()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        // Loose variant does not validate; result is a non-canonical enum value.
        CKR r = garbage.ToCKR();
        Assert.Equal((ulong)0xDEADBEEF, (ulong)r);
    }
}
