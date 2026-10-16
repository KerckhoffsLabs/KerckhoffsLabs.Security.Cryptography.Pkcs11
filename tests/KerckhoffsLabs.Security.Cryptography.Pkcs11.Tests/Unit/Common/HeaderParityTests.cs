using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// Behaviour that comes with the PKCS#11 v3.2 constants: the new KDF ids round-trip through
/// <c>CK_ULONG</c>, and the new flag bits surface through their accessors. The constant values
/// themselves, aliases included, are checked against the header by <see cref="HeaderConstantParityTests"/>.
/// </summary>
public sealed class HeaderParityTests
{
    [Fact]
    public void Ckd_NewKdf_AllDefinedAndRoundTrip()
    {
        // 0x0A..0x1A inclusive are the 17 newly added KDF ids.
        for (ulong v = 0x0A; v <= 0x1A; v++)
        {
            Assert.True(Enum.IsDefined((CKD)v), $"CKD value 0x{v:X} should be defined");
            Assert.Equal(v, (ulong)((CKD)v).ToCULong());
        }
    }

    [Fact]
    public void MechanismFlags_MessageAndEcAccessors_ReflectBits()
    {
        ulong bits =
            CKF.CKF_MESSAGE_ENCRYPT | CKF.CKF_MESSAGE_DECRYPT |
            CKF.CKF_MESSAGE_SIGN | CKF.CKF_MESSAGE_VERIFY |
            CKF.CKF_MULTI_MESSAGE | CKF.CKF_EC_OID |
            CKF.CKF_EC_CURVENAME;
        var flags = new MechanismFlags(bits);

        Assert.True(flags.MessageEncrypt);
        Assert.True(flags.MessageDecrypt);
        Assert.True(flags.MessageSign);
        Assert.True(flags.MessageVerify);
        Assert.True(flags.MultiMessage);
        Assert.True(flags.EcOid);
        Assert.True(flags.EcCurveName);

        var empty = new MechanismFlags(0UL);
        Assert.False(empty.MessageEncrypt);
        Assert.False(empty.EcCurveName);
    }

    [Fact]
    public void TokenFlags_SeedRandomRequired_ReflectsBit()
    {
        Assert.True(new TokenFlags(CKF.CKF_SEED_RANDOM_REQUIRED).SeedRandomRequired);
        Assert.False(new TokenFlags(0UL).SeedRandomRequired);
    }
}
