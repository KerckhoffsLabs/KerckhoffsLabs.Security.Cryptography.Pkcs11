using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The raw-block constructor of <see cref="Mechanism"/> holds every standard mechanism whose parameter has
/// a fixed layout to that layout's length (<see cref="MechanismParameterLength"/>), and the struct sizes it
/// uses are the sizes PKCS#11 v3.2's <c>pkcs11t.h</c> gives them.
/// </summary>
public sealed class MechanismParameterLengthTests
{
    // One mechanism for each parameter layout, with the length its parameter must be on this platform.
    public static TheoryData<CKM, int> FixedLayouts => new()
    {
        { CKM.CKM_CAMELLIA_CBC, 16 }, { CKM.CKM_ARIA_CBC_PAD, 16 }, { CKM.CKM_SEED_CBC, 16 }, { CKM.CKM_TWOFISH_CBC, 16 },
        { CKM.CKM_AES_CTS, 16 }, { CKM.CKM_AES_CFB1, 16 }, { CKM.CKM_AES_XTS, 16 },
        { CKM.CKM_BLOWFISH_CBC, 8 }, { CKM.CKM_CAST128_CBC, 8 }, { CKM.CKM_IDEA_CBC_PAD, 8 }, { CKM.CKM_CDMF_CBC, 8 },
        { CKM.CKM_SKIPJACK_CBC64, 24 }, { CKM.CKM_BATON_CBC128, 24 }, { CKM.CKM_JUNIPER_COUNTER, 24 },
        { CKM.CKM_SSL3_PRE_MASTER_KEY_GEN, 2 }, { CKM.CKM_WTLS_PRE_MASTER_KEY_GEN, 1 },
        { CKM.CKM_SHA256_HMAC_GENERAL, Pkcs11Marshal.SizeOf<CK_MAC_GENERAL_PARAMS>() },
        { CKM.CKM_AES_CMAC_GENERAL, Pkcs11Marshal.SizeOf<CK_MAC_GENERAL_PARAMS>() },
        { CKM.CKM_RC2_ECB, Pkcs11Marshal.SizeOf<CK_RC2_PARAMS>() },
        { CKM.CKM_CONCATENATE_BASE_AND_KEY, UnmanagedMemory.NativeULongSize },
        { CKM.CKM_AES_CTR, Pkcs11Marshal.SizeOf<CK_AES_CTR_PARAMS>() },
        { CKM.CKM_SHA256_RSA_PKCS_PSS, Pkcs11Marshal.SizeOf<CK_RSA_PKCS_PSS_PARAMS>() },
        { CKM.CKM_RSA_PKCS_OAEP, Pkcs11Marshal.SizeOf<CK_RSA_PKCS_OAEP_PARAMS>() },
        { CKM.CKM_ECDH1_DERIVE, Pkcs11Marshal.SizeOf<CK_ECDH1_DERIVE_PARAMS>() },
        { CKM.CKM_HKDF_DERIVE, Pkcs11Marshal.SizeOf<CK_HKDF_PARAMS>() },
        { CKM.CKM_TLS12_MASTER_KEY_DERIVE, Pkcs11Marshal.SizeOf<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>() },
        { CKM.CKM_PBE_SHA1_DES3_EDE_CBC, Pkcs11Marshal.SizeOf<CK_PBE_PARAMS>() },
        { CKM.CKM_AES_CBC_ENCRYPT_DATA, Pkcs11Marshal.SizeOf<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() },
        { CKM.CKM_CONCATENATE_BASE_AND_DATA, Pkcs11Marshal.SizeOf<CK_KEY_DERIVATION_STRING_DATA>() },
        { CKM.CKM_HASH_ML_DSA, Pkcs11Marshal.SizeOf<CK_HASH_SIGN_ADDITIONAL_CONTEXT>() },
    };

    [Theory]
    [MemberData(nameof(FixedLayouts))]
    public void Ctor_TheLayoutsLength_IsTaken(CKM type, int length)
    {
        var mech = new Mechanism(type, new byte[length]);
        using var scope = new MechanismParameterScope();

        Assert.Equal((ulong)length, (ulong)mech.Marshal(scope, out _).ParameterLen);
    }

    // One byte short, one over, and empty: the token would read past the first or be handed a parameter
    // that is not there.
    [Theory]
    [MemberData(nameof(FixedLayouts))]
    public void Ctor_AnyOtherLength_Throws(CKM type, int length)
    {
        foreach (int wrong in (int[])[0, length - 1, length + 1])
        {
            var ex = Assert.Throws<ArgumentException>(() => new Mechanism(type, new byte[wrong]));
            Assert.Equal("parameter", ex.ParamName);
            Assert.Contains($"{type} takes ", ex.Message, StringComparison.Ordinal);
            Assert.Contains($"not {wrong} bytes", ex.Message, StringComparison.Ordinal);
        }
    }

    // A parameter PKCS#11 makes optional is taken empty, or at exactly its layout's length.
    public static TheoryData<CKM, int> OptionalLayouts => new()
    {
        { CKM.CKM_AES_KEY_WRAP, 8 }, { CKM.CKM_AES_KEY_WRAP_PAD, 8 }, { CKM.CKM_AES_KEY_WRAP_KWP, 4 }, { CKM.CKM_GOST28147, 8 },
        { CKM.CKM_EDDSA, Pkcs11Marshal.SizeOf<CK_EDDSA_PARAMS>() },
        { CKM.CKM_ML_DSA, Pkcs11Marshal.SizeOf<CK_SIGN_ADDITIONAL_CONTEXT>() },
        { CKM.CKM_HASH_SLH_DSA_SHA256, Pkcs11Marshal.SizeOf<CK_SIGN_ADDITIONAL_CONTEXT>() },
        { CKM.CKM_HOTP, Pkcs11Marshal.SizeOf<CK_OTP_PARAMS>() },
    };

    [Theory]
    [MemberData(nameof(OptionalLayouts))]
    public void Ctor_OptionalParameter_IsTakenEmptyOrAtItsLength(CKM type, int length)
    {
        _ = new Mechanism(type, ReadOnlySpan<byte>.Empty);
        _ = new Mechanism(type, new byte[length]);
        Assert.Throws<ArgumentException>(() => new Mechanism(type, new byte[length - 1]));
        Assert.Throws<ArgumentException>(() => new Mechanism(type, new byte[length + 1]));
    }

    // Every rule, over every mechanism this library names: each length it allows is taken, and the length one
    // past the longest is refused with a message naming the mechanism.
    [Fact]
    public void EveryRule_TakesItsLengths_AndRefusesALongerBlock()
    {
        int ruled = 0;
        foreach (CKM type in Enum.GetValues<CKM>().Distinct())
        {
            if (MechanismParameterLength.For(type) is not { } rule)
                continue;
            ruled++;
            Assert.NotEmpty(rule.Lengths);
            foreach (int length in rule.Lengths)
                _ = new Mechanism(type, new byte[length]);
            int tooLong = rule.Lengths.Max() + 1;
            var ex = Assert.Throws<ArgumentException>(() => new Mechanism(type, new byte[tooLong]));
            Assert.StartsWith($"{type} takes {rule.What} as its parameter", ex.Message, StringComparison.Ordinal);
        }
        Assert.True(ruled > 200, $"Only {ruled} mechanisms have a parameter rule.");
    }

    // A mechanism whose parameter type depends on the function it is used with takes the size of any of them.
    [Fact]
    public void Ctor_AesGcm_TakesEachOfItsStructs()
    {
        foreach (int size in (int[])[Pkcs11Marshal.SizeOf<CK_GCM_PARAMS>(), Pkcs11Marshal.SizeOf<CK_GCM_MESSAGE_PARAMS>(), Pkcs11Marshal.SizeOf<CK_GCM_WRAP_PARAMS>()])
            _ = new Mechanism(CKM.CKM_AES_GCM, new byte[size]);
        var ex = Assert.Throws<ArgumentException>(() => new Mechanism(CKM.CKM_AES_GCM, new byte[12]));
        Assert.Contains(nameof(CK_GCM_PARAMS), ex.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(CK_GCM_WRAP_PARAMS), ex.Message, StringComparison.Ordinal);
    }

    // The sizes the rules use, for both layouts, against PKCS#11 v3.2's pkcs11t.h: natural alignment with
    // 8-byte CK_ULONG and pointers on LP64 (Linux, macOS), and #pragma pack(1) with a 4-byte CK_ULONG on
    // 64-bit Windows. Each layout is measured on its own platform: the packed sibling still uses this
    // platform's CK_ULONG and pointer, so the Windows sizes are checked by the 64-bit Windows legs and the
    // LP64 ones by Linux and macOS.
    public static TheoryData<string, int, int> StructSizes => new()
    {
        { nameof(CK_MAC_GENERAL_PARAMS), 8, 4 }, { nameof(CK_RC2_PARAMS), 8, 4 }, { nameof(CK_EXTRACT_PARAMS), 8, 4 },
        { nameof(CK_XEDDSA_PARAMS), 8, 4 }, { nameof(CK_RC2_CBC_PARAMS), 16, 12 }, { nameof(CK_RC2_MAC_GENERAL_PARAMS), 16, 8 },
        { nameof(CK_RC5_PARAMS), 16, 8 }, { nameof(CK_RC5_MAC_GENERAL_PARAMS), 24, 12 }, { nameof(CK_AES_CTR_PARAMS), 24, 20 },
        { nameof(CK_CAMELLIA_CTR_PARAMS), 24, 20 }, { nameof(CK_RSA_PKCS_PSS_PARAMS), 24, 12 }, { nameof(CK_TLS_MAC_PARAMS), 24, 12 },
        { nameof(CK_GCM_PARAMS), 48, 32 }, { nameof(CK_GCM_MESSAGE_PARAMS), 48, 32 }, { nameof(CK_GCM_WRAP_PARAMS), 56, 36 },
        { nameof(CK_CCM_PARAMS), 48, 32 }, { nameof(CK_CCM_MESSAGE_PARAMS), 56, 36 }, { nameof(CK_CCM_WRAP_PARAMS), 64, 40 },
        { nameof(CK_RSA_PKCS_OAEP_PARAMS), 40, 24 }, { nameof(CK_RSA_AES_KEY_WRAP_PARAMS), 16, 12 },
        { nameof(CK_ECDH1_DERIVE_PARAMS), 40, 28 }, { nameof(CK_ECMQV_DERIVE_PARAMS), 80, 52 },
        { nameof(CK_ECDH_AES_KEY_WRAP_PARAMS), 32, 20 }, { nameof(CK_X9_42_DH1_DERIVE_PARAMS), 40, 28 },
        { nameof(CK_X9_42_DH2_DERIVE_PARAMS), 72, 48 }, { nameof(CK_X9_42_MQV_DERIVE_PARAMS), 80, 52 },
        { nameof(CK_KEA_DERIVE_PARAMS), 48, 33 }, { nameof(CK_DSA_PARAMETER_GEN_PARAM), 32, 20 },
        { nameof(CK_RC5_CBC_PARAMS), 32, 20 }, { nameof(CK_DES_CBC_ENCRYPT_DATA_PARAMS), 24, 20 },
        { nameof(CK_AES_CBC_ENCRYPT_DATA_PARAMS), 32, 28 }, { nameof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS), 32, 28 },
        { nameof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS), 32, 28 }, { nameof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS), 32, 28 },
        { nameof(CK_KEY_DERIVATION_STRING_DATA), 16, 12 }, { nameof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS), 88, 68 },
        { nameof(CK_SKIPJACK_RELAYX_PARAMS), 112, 84 }, { nameof(CK_PBE_PARAMS), 48, 36 },
        { nameof(CK_PKCS5_PBKD2_PARAMS2), 72, 48 }, { nameof(CK_PKCS5_PBKD2_PARAMS), 72, 52 },
        { nameof(CK_KEY_WRAP_SET_OAEP_PARAMS), 24, 13 }, { nameof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS), 40, 32 },
        { nameof(CK_SSL3_KEY_MAT_PARAMS), 72, 45 }, { nameof(CK_TLS_PRF_PARAMS), 48, 40 },
        { nameof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS), 48, 36 }, { nameof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS), 32, 24 },
        { nameof(CK_TLS12_KEY_MAT_PARAMS), 80, 49 }, { nameof(CK_TLS_KDF_PARAMS), 72, 52 },
        { nameof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS), 48, 36 }, { nameof(CK_WTLS_PRF_PARAMS), 56, 44 },
        { nameof(CK_WTLS_KEY_MAT_PARAMS), 88, 53 }, { nameof(CK_CMS_SIG_PARAMS), 64, 52 }, { nameof(CK_KIP_PARAMS), 32, 24 },
        { nameof(CK_OTP_PARAMS), 16, 12 }, { nameof(CK_GOSTR3410_KEY_WRAP_PARAMS), 40, 28 },
        { nameof(CK_GOSTR3410_DERIVE_PARAMS), 40, 28 }, { nameof(CK_SP800_108_KDF_PARAMS), 40, 28 },
        { nameof(CK_SP800_108_FEEDBACK_KDF_PARAMS), 56, 40 }, { nameof(CK_CHACHA20_PARAMS), 32, 24 },
        { nameof(CK_SALSA20_PARAMS), 24, 20 }, { nameof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), 32, 24 },
        { nameof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), 24, 20 }, { nameof(CK_X3DH_INITIATE_PARAMS), 56, 36 },
        { nameof(CK_X3DH_RESPOND_PARAMS), 48, 40 }, { nameof(CK_X2RATCHET_INITIALIZE_PARAMS), 64, 33 },
        { nameof(CK_X2RATCHET_RESPOND_PARAMS), 64, 33 }, { nameof(CK_HKDF_PARAMS), 64, 38 },
        { nameof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS), 40, 21 }, { nameof(CK_IKE_PRF_DERIVE_PARAMS), 56, 34 },
        { nameof(CK_IKE1_PRF_DERIVE_PARAMS), 72, 38 }, { nameof(CK_IKE1_EXTENDED_DERIVE_PARAMS), 40, 21 },
        { nameof(CK_EDDSA_PARAMS), 24, 13 }, { nameof(CK_SIGN_ADDITIONAL_CONTEXT), 24, 16 },
        { nameof(CK_HASH_SIGN_ADDITIONAL_CONTEXT), 32, 20 },
    };

    [Theory]
    [MemberData(nameof(StructSizes))]
    public void StructSize_MatchesTheHeader(string name, int lp64, int windows)
    {
        Func<bool, int> size = Sizes[name];
        if (IntPtr.Size != 8)
            Assert.Skip("A 32-bit layout, which the header table does not list.");
        if (OperatingSystem.IsWindows())
            Assert.Equal(windows, size(true));
        else
            Assert.Equal(lp64, size(false));
    }

    private static readonly Dictionary<string, Func<bool, int>> Sizes = new()
    {
        [nameof(CK_MAC_GENERAL_PARAMS)] = Pkcs11Marshal.SizeOf<CK_MAC_GENERAL_PARAMS>,
        [nameof(CK_RC2_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC2_PARAMS>,
        [nameof(CK_EXTRACT_PARAMS)] = Pkcs11Marshal.SizeOf<CK_EXTRACT_PARAMS>,
        [nameof(CK_XEDDSA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_XEDDSA_PARAMS>,
        [nameof(CK_RC2_CBC_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC2_CBC_PARAMS>,
        [nameof(CK_RC2_MAC_GENERAL_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC2_MAC_GENERAL_PARAMS>,
        [nameof(CK_RC5_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC5_PARAMS>,
        [nameof(CK_RC5_MAC_GENERAL_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC5_MAC_GENERAL_PARAMS>,
        [nameof(CK_AES_CTR_PARAMS)] = Pkcs11Marshal.SizeOf<CK_AES_CTR_PARAMS>,
        [nameof(CK_CAMELLIA_CTR_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CAMELLIA_CTR_PARAMS>,
        [nameof(CK_RSA_PKCS_PSS_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RSA_PKCS_PSS_PARAMS>,
        [nameof(CK_TLS_MAC_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS_MAC_PARAMS>,
        [nameof(CK_GCM_PARAMS)] = Pkcs11Marshal.SizeOf<CK_GCM_PARAMS>,
        [nameof(CK_GCM_MESSAGE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_GCM_MESSAGE_PARAMS>,
        [nameof(CK_GCM_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_GCM_WRAP_PARAMS>,
        [nameof(CK_CCM_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CCM_PARAMS>,
        [nameof(CK_CCM_MESSAGE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CCM_MESSAGE_PARAMS>,
        [nameof(CK_CCM_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CCM_WRAP_PARAMS>,
        [nameof(CK_RSA_PKCS_OAEP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RSA_PKCS_OAEP_PARAMS>,
        [nameof(CK_RSA_AES_KEY_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RSA_AES_KEY_WRAP_PARAMS>,
        [nameof(CK_ECDH1_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_ECDH1_DERIVE_PARAMS>,
        [nameof(CK_ECMQV_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_ECMQV_DERIVE_PARAMS>,
        [nameof(CK_ECDH_AES_KEY_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_ECDH_AES_KEY_WRAP_PARAMS>,
        [nameof(CK_X9_42_DH1_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X9_42_DH1_DERIVE_PARAMS>,
        [nameof(CK_X9_42_DH2_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X9_42_DH2_DERIVE_PARAMS>,
        [nameof(CK_X9_42_MQV_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X9_42_MQV_DERIVE_PARAMS>,
        [nameof(CK_KEA_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_KEA_DERIVE_PARAMS>,
        [nameof(CK_DSA_PARAMETER_GEN_PARAM)] = Pkcs11Marshal.SizeOf<CK_DSA_PARAMETER_GEN_PARAM>,
        [nameof(CK_RC5_CBC_PARAMS)] = Pkcs11Marshal.SizeOf<CK_RC5_CBC_PARAMS>,
        [nameof(CK_DES_CBC_ENCRYPT_DATA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_DES_CBC_ENCRYPT_DATA_PARAMS>,
        [nameof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_AES_CBC_ENCRYPT_DATA_PARAMS>,
        [nameof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>,
        [nameof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>,
        [nameof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>,
        [nameof(CK_KEY_DERIVATION_STRING_DATA)] = Pkcs11Marshal.SizeOf<CK_KEY_DERIVATION_STRING_DATA>,
        [nameof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>,
        [nameof(CK_SKIPJACK_RELAYX_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SKIPJACK_RELAYX_PARAMS>,
        [nameof(CK_PBE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_PBE_PARAMS>,
        [nameof(CK_PKCS5_PBKD2_PARAMS2)] = Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS2>,
        [nameof(CK_PKCS5_PBKD2_PARAMS)] = Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS>,
        [nameof(CK_KEY_WRAP_SET_OAEP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_KEY_WRAP_SET_OAEP_PARAMS>,
        [nameof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>,
        [nameof(CK_SSL3_KEY_MAT_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SSL3_KEY_MAT_PARAMS>,
        [nameof(CK_TLS_PRF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS_PRF_PARAMS>,
        [nameof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>,
        [nameof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>,
        [nameof(CK_TLS12_KEY_MAT_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS12_KEY_MAT_PARAMS>,
        [nameof(CK_TLS_KDF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_TLS_KDF_PARAMS>,
        [nameof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>,
        [nameof(CK_WTLS_PRF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_WTLS_PRF_PARAMS>,
        [nameof(CK_WTLS_KEY_MAT_PARAMS)] = Pkcs11Marshal.SizeOf<CK_WTLS_KEY_MAT_PARAMS>,
        [nameof(CK_CMS_SIG_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CMS_SIG_PARAMS>,
        [nameof(CK_KIP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_KIP_PARAMS>,
        [nameof(CK_OTP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_OTP_PARAMS>,
        [nameof(CK_GOSTR3410_KEY_WRAP_PARAMS)] = Pkcs11Marshal.SizeOf<CK_GOSTR3410_KEY_WRAP_PARAMS>,
        [nameof(CK_GOSTR3410_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_GOSTR3410_DERIVE_PARAMS>,
        [nameof(CK_SP800_108_KDF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SP800_108_KDF_PARAMS>,
        [nameof(CK_SP800_108_FEEDBACK_KDF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SP800_108_FEEDBACK_KDF_PARAMS>,
        [nameof(CK_CHACHA20_PARAMS)] = Pkcs11Marshal.SizeOf<CK_CHACHA20_PARAMS>,
        [nameof(CK_SALSA20_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SALSA20_PARAMS>,
        [nameof(CK_SALSA20_CHACHA20_POLY1305_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_PARAMS>,
        [nameof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)] = Pkcs11Marshal.SizeOf<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>,
        [nameof(CK_X3DH_INITIATE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X3DH_INITIATE_PARAMS>,
        [nameof(CK_X3DH_RESPOND_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X3DH_RESPOND_PARAMS>,
        [nameof(CK_X2RATCHET_INITIALIZE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X2RATCHET_INITIALIZE_PARAMS>,
        [nameof(CK_X2RATCHET_RESPOND_PARAMS)] = Pkcs11Marshal.SizeOf<CK_X2RATCHET_RESPOND_PARAMS>,
        [nameof(CK_HKDF_PARAMS)] = Pkcs11Marshal.SizeOf<CK_HKDF_PARAMS>,
        [nameof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>,
        [nameof(CK_IKE_PRF_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_IKE_PRF_DERIVE_PARAMS>,
        [nameof(CK_IKE1_PRF_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_IKE1_PRF_DERIVE_PARAMS>,
        [nameof(CK_IKE1_EXTENDED_DERIVE_PARAMS)] = Pkcs11Marshal.SizeOf<CK_IKE1_EXTENDED_DERIVE_PARAMS>,
        [nameof(CK_EDDSA_PARAMS)] = Pkcs11Marshal.SizeOf<CK_EDDSA_PARAMS>,
        [nameof(CK_SIGN_ADDITIONAL_CONTEXT)] = Pkcs11Marshal.SizeOf<CK_SIGN_ADDITIONAL_CONTEXT>,
        [nameof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)] = Pkcs11Marshal.SizeOf<CK_HASH_SIGN_ADDITIONAL_CONTEXT>,
    };
}
