using System;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using Microsoft.DotNet.XUnitExtensions;
using Xunit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

/// <summary>
/// Pins the marshalled size of every native interop struct, separately per platform.
/// Catches BL-001-class struct-layout drift the moment it lands. The Unix expected
/// values were captured from a probe on Linux x64 at plan-creation time. The Windows
/// expected values are the OASIS pkcs11.h spec ABI (#pragma pack(push, 1)) and are
/// added struct-by-struct as types are migrated to [PackedForPkcs11].
/// </summary>
public sealed class MarshalSizeOfTests
{
    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact]
    public void CK_VERSION_SizeIs2()
    {
        Assert.Equal(2, Marshal.SizeOf<CK_VERSION>());
    }

    [Fact]
    public void CK_INFO_Windows_SiblingIsGenerated()
    {
        var winName = typeof(CK_INFO).FullName + "_Windows";
        var winType = typeof(CK_INFO).Assembly.GetType(winName);
        Assert.NotNull(winType);
    }

    /// <summary>
    /// Pins the natural-alignment (Pack default) layout that PKCS#11 produces on
    /// Linux/macOS x64. Any drift here means the unified <c>T</c> type changed shape.
    /// CK_FUNCTION_LIST variants are intentionally excluded — their size depends on
    /// platform-specific function pointer counts and is not part of this test's scope.
    /// </summary>
    [ConditionalTheory(nameof(IsUnix))]
    // BEGIN PROBED InlineData — Linux x64, LP64
    [InlineData(typeof(CK_ASYNC_DATA), 40)]
    [InlineData(typeof(CK_ATTRIBUTE), 24)]
    [InlineData(typeof(CK_C_INITIALIZE_ARGS), 48)]
    [InlineData(typeof(CK_INFO), 88)]
    [InlineData(typeof(CK_INTERFACE), 24)]
    [InlineData(typeof(CK_MECHANISM), 24)]
    [InlineData(typeof(CK_MECHANISM_INFO), 24)]
    [InlineData(typeof(CK_SESSION_INFO), 32)]
    [InlineData(typeof(CK_SLOT_INFO), 112)]
    [InlineData(typeof(CK_TOKEN_INFO), 208)]
    [InlineData(typeof(CK_VERSION), 2)]
    [InlineData(typeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS), 32)]
    [InlineData(typeof(CK_AES_CTR_PARAMS), 24)]
    [InlineData(typeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS), 32)]
    [InlineData(typeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS), 32)]
    [InlineData(typeof(CK_CAMELLIA_CTR_PARAMS), 24)]
    [InlineData(typeof(CK_CCM_MESSAGE_PARAMS), 56)]
    [InlineData(typeof(CK_CCM_PARAMS), 48)]
    [InlineData(typeof(CK_CCM_WRAP_PARAMS), 64)]
    [InlineData(typeof(CK_CHACHA20_PARAMS), 32)]
    [InlineData(typeof(CK_CMS_SIG_PARAMS), 64)]
    [InlineData(typeof(CK_DERIVED_KEY), 24)]
    [InlineData(typeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS), 24)]
    [InlineData(typeof(CK_DSA_PARAMETER_GEN_PARAM), 32)]
    [InlineData(typeof(CK_ECDH_AES_KEY_WRAP_PARAMS), 32)]
    [InlineData(typeof(CK_ECDH1_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_ECDH2_DERIVE_PARAMS), 72)]
    [InlineData(typeof(CK_ECMQV_DERIVE_PARAMS), 80)]
    [InlineData(typeof(CK_EDDSA_PARAMS), 24)]
    [InlineData(typeof(CK_EXTRACT_PARAMS), 8)]
    [InlineData(typeof(CK_GCM_MESSAGE_PARAMS), 48)]
    [InlineData(typeof(CK_GCM_PARAMS), 48)]
    [InlineData(typeof(CK_GCM_WRAP_PARAMS), 56)]
    [InlineData(typeof(CK_GOSTR3410_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_GOSTR3410_KEY_WRAP_PARAMS), 40)]
    [InlineData(typeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT), 32)]
    [InlineData(typeof(CK_HKDF_PARAMS), 64)]
    [InlineData(typeof(CK_IKE_PRF_DERIVE_PARAMS), 56)]
    [InlineData(typeof(CK_IKE1_EXTENDED_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_IKE1_PRF_DERIVE_PARAMS), 72)]
    [InlineData(typeof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_KEA_DERIVE_PARAMS), 48)]
    [InlineData(typeof(CK_KEY_DERIVATION_STRING_DATA), 16)]
    [InlineData(typeof(CK_KEY_WRAP_SET_OAEP_PARAMS), 24)]
    [InlineData(typeof(CK_KIP_PARAMS), 32)]
    [InlineData(typeof(CK_MAC_GENERAL_PARAMS), 8)]
    [InlineData(typeof(CK_OTP_PARAM), 24)]
    [InlineData(typeof(CK_OTP_PARAMS), 16)]
    [InlineData(typeof(CK_OTP_SIGNATURE_INFO), 16)]
    [InlineData(typeof(CK_PBE_PARAMS), 48)]
    [InlineData(typeof(CK_PKCS5_PBKD2_PARAMS), 72)]
    [InlineData(typeof(CK_PKCS5_PBKD2_PARAMS2), 72)]
    [InlineData(typeof(CK_PRF_DATA_PARAM), 24)]
    [InlineData(typeof(CK_RC2_CBC_PARAMS), 16)]
    [InlineData(typeof(CK_RC2_MAC_GENERAL_PARAMS), 16)]
    [InlineData(typeof(CK_RC2_PARAMS), 8)]
    [InlineData(typeof(CK_RC5_CBC_PARAMS), 32)]
    [InlineData(typeof(CK_RC5_MAC_GENERAL_PARAMS), 24)]
    [InlineData(typeof(CK_RC5_PARAMS), 16)]
    [InlineData(typeof(CK_RSA_AES_KEY_WRAP_PARAMS), 16)]
    [InlineData(typeof(CK_RSA_PKCS_OAEP_PARAMS), 40)]
    [InlineData(typeof(CK_RSA_PKCS_PSS_PARAMS), 24)]
    [InlineData(typeof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), 24)]
    [InlineData(typeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), 32)]
    [InlineData(typeof(CK_SALSA20_PARAMS), 24)]
    [InlineData(typeof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS), 32)]
    [InlineData(typeof(CK_SIGN_ADDITIONAL_CONTEXT), 24)]
    [InlineData(typeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS), 88)]
    [InlineData(typeof(CK_SKIPJACK_RELAYX_PARAMS), 112)]
    [InlineData(typeof(CK_SP800_108_COUNTER_FORMAT), 16)]
    [InlineData(typeof(CK_SP800_108_DKM_LENGTH_FORMAT), 24)]
    [InlineData(typeof(CK_SP800_108_FEEDBACK_KDF_PARAMS), 56)]
    [InlineData(typeof(CK_SP800_108_KDF_PARAMS), 40)]
    [InlineData(typeof(CK_SSL3_KEY_MAT_OUT), 48)]
    [InlineData(typeof(CK_SSL3_KEY_MAT_PARAMS), 72)]
    [InlineData(typeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_SSL3_RANDOM_DATA), 32)]
    [InlineData(typeof(CK_TLS_KDF_PARAMS), 72)]
    [InlineData(typeof(CK_TLS_MAC_PARAMS), 24)]
    [InlineData(typeof(CK_TLS_PRF_PARAMS), 48)]
    [InlineData(typeof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS), 32)]
    [InlineData(typeof(CK_TLS12_KEY_MAT_PARAMS), 80)]
    [InlineData(typeof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS), 48)]
    [InlineData(typeof(CK_WTLS_KEY_MAT_OUT), 24)]
    [InlineData(typeof(CK_WTLS_KEY_MAT_PARAMS), 88)]
    [InlineData(typeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS), 48)]
    [InlineData(typeof(CK_WTLS_PRF_PARAMS), 56)]
    [InlineData(typeof(CK_WTLS_RANDOM_DATA), 32)]
    [InlineData(typeof(CK_X2RATCHET_INITIALIZE_PARAMS), 64)]
    [InlineData(typeof(CK_X2RATCHET_RESPOND_PARAMS), 64)]
    [InlineData(typeof(CK_X3DH_INITIATE_PARAMS), 56)]
    [InlineData(typeof(CK_X3DH_RESPOND_PARAMS), 48)]
    [InlineData(typeof(CK_X9_42_DH1_DERIVE_PARAMS), 40)]
    [InlineData(typeof(CK_X9_42_DH2_DERIVE_PARAMS), 72)]
    [InlineData(typeof(CK_X9_42_MQV_DERIVE_PARAMS), 80)]
    [InlineData(typeof(CK_XEDDSA_PARAMS), 8)]
    // END PROBED InlineData
    public void UnifiedStructSize_OnUnix(Type t, int expectedSize)
    {
        Assert.Equal(expectedSize, Marshal.SizeOf(t));
    }

    /// <summary>
    /// Pins the Pack=1 layout emitted by the source generator for Windows-bound siblings.
    /// These run on ANY platform (the IL layout is baked at compile time). As structs
    /// are migrated to <c>[PackedForPkcs11]</c> in subsequent tasks, add an entry here.
    /// </summary>
    [Theory]
    [InlineData("CK_VERSION_Windows", 2)]
    [InlineData("CK_INFO_Windows", 76)]
    public void WindowsSiblingStructSize(string typeName, int expectedSize)
    {
        var t = typeof(CK_INFO).Assembly.GetType(
            "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native." + typeName);
        Assert.NotNull(t);
        Assert.Equal(expectedSize, Marshal.SizeOf(t!));
    }
}
