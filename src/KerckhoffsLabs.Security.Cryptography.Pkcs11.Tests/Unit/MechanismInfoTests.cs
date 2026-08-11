using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class MechanismInfoTests
{
    [Fact]
    public void Decodes_AllFields()
    {
        var native = new CK_MECHANISM_INFO
        {
            MinKeySize = (NativeCULong)128UL,
            MaxKeySize = (NativeCULong)256UL,
            Flags = (NativeCULong)(CKF.CKF_ENCRYPT | CKF.CKF_DECRYPT),
        };

        var info = new MechanismInfo(CKM.CKM_AES_GCM, native);

        Assert.Equal(CKM.CKM_AES_GCM, info.Mechanism);
        Assert.Equal(128UL, info.MinKeySize);
        Assert.Equal(256UL, info.MaxKeySize);
        Assert.True(info.MechanismFlags.Encrypt);
        Assert.True(info.MechanismFlags.Decrypt);
        Assert.False(info.MechanismFlags.Sign);
    }

    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN)]
    [InlineData(CKM.CKM_EC_KEY_PAIR_GEN)]
    [InlineData(CKM.CKM_ML_DSA)]
    public void Mechanism_Preserved(CKM mechanism)
    {
        var info = new MechanismInfo(mechanism, new CK_MECHANISM_INFO());
        Assert.Equal(mechanism, info.Mechanism);
    }

    [Fact]
    public void KeySizes_ZeroForSymmetricMechanismsWithoutRange()
    {
        var info = new MechanismInfo(CKM.CKM_SHA256, new CK_MECHANISM_INFO
        {
            Flags = (NativeCULong)CKF.CKF_DIGEST,
        });

        Assert.Equal(0UL, info.MinKeySize);
        Assert.Equal(0UL, info.MaxKeySize);
        Assert.True(info.MechanismFlags.Digest);
    }
}
