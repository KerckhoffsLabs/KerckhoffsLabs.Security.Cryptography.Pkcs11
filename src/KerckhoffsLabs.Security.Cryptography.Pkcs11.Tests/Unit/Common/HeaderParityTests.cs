using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// Pins the constants added for PKCS#11 v3.2 header parity to their exact pkcs11t.h values, and
/// verifies the new flag accessors. Guards against typos in the literal values and against the
/// aliases drifting away from their canonical members.
/// </summary>
public sealed class HeaderParityTests
{
    [Theory]
    [InlineData(CKK.CKK_XMSS, 0x47)]
    [InlineData(CKK.CKK_XMSSMT, 0x48)]
    public void Ckk_NewKeyTypes_MatchHeader(CKK value, int expected) =>
        Assert.Equal(expected, (int)value);

    [Theory]
    [InlineData(CKG.CKG_MGF1_SHA3_224, 0x06)]
    [InlineData(CKG.CKG_MGF1_SHA3_256, 0x07)]
    [InlineData(CKG.CKG_MGF1_SHA3_384, 0x08)]
    [InlineData(CKG.CKG_MGF1_SHA3_512, 0x09)]
    public void Ckg_NewMgf_MatchHeader(CKG value, int expected) =>
        Assert.Equal(expected, (int)value);

    [Theory]
    [InlineData(CKD.CKD_SHA3_224_KDF, 0x0A)]
    [InlineData(CKD.CKD_SHA512_KDF_SP800, 0x12)]
    [InlineData(CKD.CKD_SHA3_512_KDF_SP800, 0x16)]
    [InlineData(CKD.CKD_BLAKE2B_160_KDF, 0x17)]
    [InlineData(CKD.CKD_BLAKE2B_512_KDF, 0x1A)]
    public void Ckd_NewKdf_MatchHeader(CKD value, int expected) =>
        Assert.Equal(expected, (int)value);

    [Fact]
    public void Ckd_NewKdf_AllDefinedAndRoundTrip()
    {
        // 0x0A..0x1A inclusive are the 17 newly added KDF ids.
        for (ulong v = 0x0A; v <= 0x1A; v++)
        {
            Assert.True(Enum.IsDefined((CKD)v), $"CKD value 0x{v:X} should be defined");
            Assert.Equal((CKD)v, ((NativeCULong)v).ToCKD());
        }
    }

    [Theory]
    [InlineData(CKM.CKM_SHA3_224_KEY_DERIVE, CKM.CKM_SHA3_224_KEY_DERIVATION)]
    [InlineData(CKM.CKM_SHA3_256_KEY_DERIVE, CKM.CKM_SHA3_256_KEY_DERIVATION)]
    [InlineData(CKM.CKM_SHA3_384_KEY_DERIVE, CKM.CKM_SHA3_384_KEY_DERIVATION)]
    [InlineData(CKM.CKM_SHA3_512_KEY_DERIVE, CKM.CKM_SHA3_512_KEY_DERIVATION)]
    [InlineData(CKM.CKM_SHAKE_128_KEY_DERIVE, CKM.CKM_SHAKE_128_KEY_DERIVATION)]
    [InlineData(CKM.CKM_SHAKE_256_KEY_DERIVE, CKM.CKM_SHAKE_256_KEY_DERIVATION)]
    public void Ckm_KeyDeriveAliases_EqualCanonical(CKM alias, CKM canonical) =>
        Assert.Equal(canonical, alias);

    [Fact]
    public void Cka_SubPrimeBits_Alias_EqualsCanonical() =>
        Assert.Equal(CKA.CKA_SUBPRIME_BITS, CKA.CKA_SUB_PRIME_BITS);

    [Theory]
    [InlineData(0x00000002UL)] // CKF_MESSAGE_ENCRYPT
    [InlineData(0x00000004UL)] // CKF_MESSAGE_DECRYPT
    [InlineData(0x00000008UL)] // CKF_MESSAGE_SIGN
    [InlineData(0x00000010UL)] // CKF_MESSAGE_VERIFY
    [InlineData(0x00000020UL)] // CKF_MULTI_MESSAGE
    [InlineData(0x00000040UL)] // CKF_FIND_OBJECTS
    [InlineData(0x00800000UL)] // CKF_EC_OID
    [InlineData(0x04000000UL)] // CKF_EC_CURVENAME
    [InlineData(0x02000000UL)] // CKF_SEED_RANDOM_REQUIRED
    public void Ckf_NewFlags_HaveExpectedBit(ulong bit)
    {
        ulong[] values =
        [
            (ulong)CKF.CKF_MESSAGE_ENCRYPT.Value, (ulong)CKF.CKF_MESSAGE_DECRYPT.Value,
            (ulong)CKF.CKF_MESSAGE_SIGN.Value, (ulong)CKF.CKF_MESSAGE_VERIFY.Value,
            (ulong)CKF.CKF_MULTI_MESSAGE.Value, (ulong)CKF.CKF_FIND_OBJECTS.Value,
            (ulong)CKF.CKF_EC_OID.Value, (ulong)CKF.CKF_EC_CURVENAME.Value,
            (ulong)CKF.CKF_SEED_RANDOM_REQUIRED.Value,
        ];
        Assert.Contains(bit, values);
    }

    [Fact]
    public void MechanismFlags_MessageAndEcAccessors_ReflectBits()
    {
        ulong bits =
            (ulong)CKF.CKF_MESSAGE_ENCRYPT.Value | (ulong)CKF.CKF_MESSAGE_DECRYPT.Value |
            (ulong)CKF.CKF_MESSAGE_SIGN.Value | (ulong)CKF.CKF_MESSAGE_VERIFY.Value |
            (ulong)CKF.CKF_MULTI_MESSAGE.Value | (ulong)CKF.CKF_EC_OID.Value |
            (ulong)CKF.CKF_EC_CURVENAME.Value;
        var flags = new MechanismFlags((NativeCULong)bits);

        Assert.True(flags.MessageEncrypt);
        Assert.True(flags.MessageDecrypt);
        Assert.True(flags.MessageSign);
        Assert.True(flags.MessageVerify);
        Assert.True(flags.MultiMessage);
        Assert.True(flags.EcOid);
        Assert.True(flags.EcCurveName);

        var empty = new MechanismFlags((NativeCULong)0UL);
        Assert.False(empty.MessageEncrypt);
        Assert.False(empty.EcCurveName);
    }

    [Fact]
    public void TokenFlags_SeedRandomRequired_ReflectsBit()
    {
        Assert.True(new TokenFlags(CKF.CKF_SEED_RANDOM_REQUIRED).SeedRandomRequired);
        Assert.False(new TokenFlags((NativeCULong)0UL).SeedRandomRequired);
    }
}
