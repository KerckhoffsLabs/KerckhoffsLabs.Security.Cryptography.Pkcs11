using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

#pragma warning disable KLPKCS11009 // RC2 is deprecated; its argument checks are the subject here

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The numeric limits the parameter constructors check before anything reaches a token, each at its
/// boundary: the last accepted value and the first refused one.
/// </summary>
public sealed class ParameterRangeTests
{
    // === CCM: the data length must fit the length field the nonce leaves (RFC 3610 §2.1) =====

    // Both CCM wrappers apply the same rule, so each case runs against both.
    public static TheoryData<string> CcmWrappers() => ["CkmAesCcmParams", "CkmCcmMessageParams"];

    private static object Ccm(string wrapper, int dataLen, int nonceLength) => wrapper == "CkmAesCcmParams"
        ? new CkmAesCcmParams(dataLen, new byte[nonceLength], default, macLen: 16)
        : CkmCcmMessageParams.ForEncrypt(dataLen, new byte[nonceLength], macBytes: 16);

    [Theory]
    [MemberData(nameof(CcmWrappers))]
    public void Ccm_NegativeDataLength_Throws(string wrapper)
        => Assert.Equal("dataLen", Assert.Throws<ArgumentOutOfRangeException>(() => Ccm(wrapper, -1, 12)).ParamName);

    [Theory]
    [MemberData(nameof(CcmWrappers))]
    public void Ccm_DataLength_IsBoundedByTheNoncesLengthField(string wrapper)
    {
        Assert.NotNull(Ccm(wrapper, 65_535, 13));
        Assert.NotNull(Ccm(wrapper, 16_777_215, 12));
        Assert.NotNull(Ccm(wrapper, int.MaxValue, 11)); // a 4-byte field holds any int

        var thirteen = Assert.Throws<ArgumentOutOfRangeException>(() => Ccm(wrapper, 65_536, 13));
        Assert.Equal("dataLen", thirteen.ParamName);
        Assert.StartsWith(
            "A 13-byte CCM nonce leaves a 2-byte length field, so the data must be shorter than 65536 bytes (RFC 3610).",
            thirteen.Message, StringComparison.Ordinal);

        var twelve = Assert.Throws<ArgumentOutOfRangeException>(() => Ccm(wrapper, 16_777_216, 12));
        Assert.StartsWith(
            "A 12-byte CCM nonce leaves a 3-byte length field, so the data must be shorter than 16777216 bytes (RFC 3610).",
            twelve.Message, StringComparison.Ordinal);
    }

    // === PQC signing context: at most 255 bytes (FIPS 204 §5.2.1, FIPS 205 §10.2.1) ==========

    [Fact]
    public void PqcContext_Of255Bytes_IsAccepted_And256_Refused()
    {
        Assert.NotNull(new CkmPqcSignParams(context: new byte[255]));
        Assert.NotNull(new CkmHashPqcSignParams(CKM.CKM_SHA256, context: new byte[255]));

        Assert.Equal("context", Assert.Throws<ArgumentException>(() => new CkmPqcSignParams(context: new byte[256])).ParamName);
        Assert.Equal("context", Assert.Throws<ArgumentException>(() => new CkmHashPqcSignParams(CKM.CKM_SHA256, context: new byte[256])).ParamName);
    }

    // === Counts that cannot be negative ======================================================

    [Fact]
    public void Pbkdf2_NegativeIterations_Throws()
    {
        Assert.Equal("iterations", Assert.Throws<ArgumentOutOfRangeException>(
            () => new CkmPkcs5Pbkd2Params([1], -1, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, [1])).ParamName);
        Assert.NotNull(new CkmPkcs5Pbkd2Params([1], 0, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, [1]));
    }

    [Fact]
    public void Rc2_NegativeEffectiveBits_Throws()
    {
        Assert.Equal("effectiveBits", Assert.Throws<ArgumentOutOfRangeException>(() => new CkmRc2Params(-1)).ParamName);
        Assert.Equal("effectiveBits", Assert.Throws<ArgumentOutOfRangeException>(() => new CkmRc2CbcParams(-1, new byte[8])).ParamName);
        Assert.NotNull(new CkmRc2Params(0));
        Assert.NotNull(new CkmRc2CbcParams(0, new byte[8]));
    }
}
