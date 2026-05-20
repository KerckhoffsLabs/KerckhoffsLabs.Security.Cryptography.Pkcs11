// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Common;

/// <summary>
/// Round-trip and validation tests for the per-enum extension methods. One representative
/// sample per enum keeps the test count reasonable; the extension implementations are
/// mechanically identical across enums. <c>ToCK*</c> always validates — there is no longer
/// a loose, non-validating variant.
/// </summary>
public class EnumExtensionsTests
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

    [Fact]
    public void ToCK_ThrowsOnUndefinedValue()
    {
        NativeCULong garbage = (NativeCULong)0xDEADBEEFu;
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKR());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKA());
        Assert.Throws<InvalidEnumValueException>(() => garbage.ToCKM());
    }
}
