using System.Reflection;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Pins the marshalled size of every native interop struct, separately per platform, so struct-layout
/// drift fails the build the moment it lands. Three sets of expectations, one per ABI:
/// <list type="bullet">
///   <item>Unix LP64 — probed on Linux x64.</item>
///   <item>Windows x64 — the OASIS pkcs11.h ABI (<c>#pragma pack(push, 1)</c>, CK_ULONG 4, pointer 8).</item>
///   <item>Windows x86 — the same ABI at ILP32 (pointer 4), derived from the x64 values.</item>
/// </list>
/// Each set is gated to the platform it describes, so on any given run two of the three are skipped.
/// </summary>
public sealed class MarshalSizeOfTests
{
    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    // Windows x64: the narrow CK_ULONG (uint) runtime asset resolves here, which is what the
    // Pack=1 sibling sizes in WindowsSiblingStructSize assume. On Unix the siblings are never used
    // at all — the unified path handles marshalling — so that theory is skipped there.
    public static bool IsWindows64 => OperatingSystem.IsWindows() && Environment.Is64BitProcess;

    // Windows x86 (ILP32): CK_ULONG is still 4, but pointers shrink to 4, so every pointer-bearing
    // sibling is smaller than on x64 and needs its own expectations.
    public static bool IsWindows32 => OperatingSystem.IsWindows() && !Environment.Is64BitProcess;

    [Fact]
    public void CK_VERSION_SizeIs2() => Assert.Equal(2, Marshal.SizeOf<CK_VERSION>());

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
    /// CK_FUNCTION_LIST variants are included: each has a fixed function-pointer count, so its
    /// LP64 size is deterministic (8-byte CK_VERSION slot + N * 8). These are the structs the
    /// loader binds against, so drift here is the most consequential kind.
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
    [InlineData(typeof(CK_FUNCTION_LIST), 552)]
    [InlineData(typeof(CK_FUNCTION_LIST_3_0), 744)]
    [InlineData(typeof(CK_FUNCTION_LIST_3_2), 840)]
    // END PROBED InlineData
    public void UnifiedStructSize_OnUnix(Type t, int expectedSize) => Assert.Equal(expectedSize, Marshal.SizeOf(t));

    /// <summary>
    /// Pins the Pack=1 layout emitted by the source generator for Windows-bound siblings.
    /// Values are the OASIS pkcs11.h Windows ABI on a 64-bit pointer: CK_ULONG = 4 bytes
    /// (LLP64 <c>unsigned long</c>), pointer = 8, <c>#pragma pack(1)</c>. Runs only on 64-bit
    /// Windows, where NativeCULong resolves to the 4-byte (uint) runtime asset these sizes assume;
    /// elsewhere the siblings are nuint-wide and never used (the unified path handles Unix), so the
    /// theory is skipped. The check is on the live <see cref="Marshal.SizeOf(System.Type)"/>, i.e.
    /// the loaded per-RID build, not the compile-time reference.
    /// </summary>
    [ConditionalTheory(nameof(IsWindows64))]
    // BEGIN Windows InlineData — OASIS Windows x64 ABI (CK_ULONG=4, ptr=8, pack=1)
    [InlineData("CK_ASYNC_DATA_Windows", 24)]
    [InlineData("CK_ATTRIBUTE_Windows", 16)]
    [InlineData("CK_C_INITIALIZE_ARGS_Windows", 44)]
    [InlineData("CK_FUNCTION_LIST_3_0_Windows", 738)]
    [InlineData("CK_FUNCTION_LIST_3_2_Windows", 834)]
    [InlineData("CK_FUNCTION_LIST_Windows", 546)]
    [InlineData("CK_INFO_Windows", 72)]
    [InlineData("CK_INTERFACE_Windows", 20)]
    [InlineData("CK_MECHANISM_INFO_Windows", 12)]
    [InlineData("CK_MECHANISM_Windows", 16)]
    [InlineData("CK_SESSION_INFO_Windows", 16)]
    [InlineData("CK_SLOT_INFO_Windows", 104)]
    [InlineData("CK_TOKEN_INFO_Windows", 160)]
    [InlineData("CK_AES_CBC_ENCRYPT_DATA_PARAMS_Windows", 28)]
    [InlineData("CK_AES_CTR_PARAMS_Windows", 20)]
    [InlineData("CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_Windows", 28)]
    [InlineData("CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_Windows", 28)]
    [InlineData("CK_CAMELLIA_CTR_PARAMS_Windows", 20)]
    [InlineData("CK_CCM_MESSAGE_PARAMS_Windows", 36)]
    [InlineData("CK_CCM_PARAMS_Windows", 32)]
    [InlineData("CK_CCM_WRAP_PARAMS_Windows", 40)]
    [InlineData("CK_CHACHA20_PARAMS_Windows", 24)]
    [InlineData("CK_CMS_SIG_PARAMS_Windows", 52)]
    [InlineData("CK_DERIVED_KEY_Windows", 20)]
    [InlineData("CK_DES_CBC_ENCRYPT_DATA_PARAMS_Windows", 20)]
    [InlineData("CK_DSA_PARAMETER_GEN_PARAM_Windows", 20)]
    [InlineData("CK_ECDH_AES_KEY_WRAP_PARAMS_Windows", 20)]
    [InlineData("CK_ECDH1_DERIVE_PARAMS_Windows", 28)]
    [InlineData("CK_ECDH2_DERIVE_PARAMS_Windows", 48)]
    [InlineData("CK_ECMQV_DERIVE_PARAMS_Windows", 52)]
    [InlineData("CK_EDDSA_PARAMS_Windows", 13)]
    [InlineData("CK_EXTRACT_PARAMS_Windows", 4)]
    [InlineData("CK_GCM_MESSAGE_PARAMS_Windows", 32)]
    [InlineData("CK_GCM_PARAMS_Windows", 32)]
    [InlineData("CK_GCM_WRAP_PARAMS_Windows", 36)]
    [InlineData("CK_GOSTR3410_DERIVE_PARAMS_Windows", 28)]
    [InlineData("CK_GOSTR3410_KEY_WRAP_PARAMS_Windows", 28)]
    [InlineData("CK_HASH_SIGN_ADDITIONAL_CONTEXT_Windows", 20)]
    [InlineData("CK_HKDF_PARAMS_Windows", 38)]
    [InlineData("CK_IKE_PRF_DERIVE_PARAMS_Windows", 34)]
    [InlineData("CK_IKE1_EXTENDED_DERIVE_PARAMS_Windows", 21)]
    [InlineData("CK_IKE1_PRF_DERIVE_PARAMS_Windows", 38)]
    [InlineData("CK_IKE2_PRF_PLUS_DERIVE_PARAMS_Windows", 21)]
    [InlineData("CK_KEA_DERIVE_PARAMS_Windows", 33)]
    [InlineData("CK_KEY_DERIVATION_STRING_DATA_Windows", 12)]
    [InlineData("CK_KEY_WRAP_SET_OAEP_PARAMS_Windows", 13)]
    [InlineData("CK_KIP_PARAMS_Windows", 24)]
    [InlineData("CK_MAC_GENERAL_PARAMS_Windows", 4)]
    [InlineData("CK_OTP_PARAM_Windows", 16)]
    [InlineData("CK_OTP_PARAMS_Windows", 12)]
    [InlineData("CK_OTP_SIGNATURE_INFO_Windows", 12)]
    [InlineData("CK_PBE_PARAMS_Windows", 36)]
    [InlineData("CK_PKCS5_PBKD2_PARAMS_Windows", 52)]
    [InlineData("CK_PKCS5_PBKD2_PARAMS2_Windows", 48)]
    [InlineData("CK_PRF_DATA_PARAM_Windows", 16)]
    [InlineData("CK_RC2_CBC_PARAMS_Windows", 12)]
    [InlineData("CK_RC2_MAC_GENERAL_PARAMS_Windows", 8)]
    [InlineData("CK_RC2_PARAMS_Windows", 4)]
    [InlineData("CK_RC5_CBC_PARAMS_Windows", 20)]
    [InlineData("CK_RC5_MAC_GENERAL_PARAMS_Windows", 12)]
    [InlineData("CK_RC5_PARAMS_Windows", 8)]
    [InlineData("CK_RSA_AES_KEY_WRAP_PARAMS_Windows", 12)]
    [InlineData("CK_RSA_PKCS_OAEP_PARAMS_Windows", 24)]
    [InlineData("CK_RSA_PKCS_PSS_PARAMS_Windows", 12)]
    [InlineData("CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_Windows", 20)]
    [InlineData("CK_SALSA20_CHACHA20_POLY1305_PARAMS_Windows", 24)]
    [InlineData("CK_SALSA20_PARAMS_Windows", 20)]
    [InlineData("CK_SEED_CBC_ENCRYPT_DATA_PARAMS_Windows", 28)]
    [InlineData("CK_SIGN_ADDITIONAL_CONTEXT_Windows", 16)]
    [InlineData("CK_SKIPJACK_PRIVATE_WRAP_PARAMS_Windows", 68)]
    [InlineData("CK_SKIPJACK_RELAYX_PARAMS_Windows", 84)]
    [InlineData("CK_SP800_108_COUNTER_FORMAT_Windows", 5)]
    [InlineData("CK_SP800_108_DKM_LENGTH_FORMAT_Windows", 9)]
    [InlineData("CK_SP800_108_FEEDBACK_KDF_PARAMS_Windows", 40)]
    [InlineData("CK_SP800_108_KDF_PARAMS_Windows", 28)]
    [InlineData("CK_SSL3_KEY_MAT_OUT_Windows", 32)]
    [InlineData("CK_SSL3_KEY_MAT_PARAMS_Windows", 45)]
    [InlineData("CK_SSL3_MASTER_KEY_DERIVE_PARAMS_Windows", 32)]
    [InlineData("CK_SSL3_RANDOM_DATA_Windows", 24)]
    [InlineData("CK_TLS_KDF_PARAMS_Windows", 52)]
    [InlineData("CK_TLS_MAC_PARAMS_Windows", 12)]
    [InlineData("CK_TLS_PRF_PARAMS_Windows", 40)]
    [InlineData("CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS_Windows", 24)]
    [InlineData("CK_TLS12_KEY_MAT_PARAMS_Windows", 49)]
    [InlineData("CK_TLS12_MASTER_KEY_DERIVE_PARAMS_Windows", 36)]
    [InlineData("CK_WTLS_KEY_MAT_OUT_Windows", 16)]
    [InlineData("CK_WTLS_KEY_MAT_PARAMS_Windows", 53)]
    [InlineData("CK_WTLS_MASTER_KEY_DERIVE_PARAMS_Windows", 36)]
    [InlineData("CK_WTLS_PRF_PARAMS_Windows", 44)]
    [InlineData("CK_WTLS_RANDOM_DATA_Windows", 24)]
    [InlineData("CK_X2RATCHET_INITIALIZE_PARAMS_Windows", 33)]
    [InlineData("CK_X2RATCHET_RESPOND_PARAMS_Windows", 33)]
    [InlineData("CK_X3DH_INITIATE_PARAMS_Windows", 36)]
    [InlineData("CK_X3DH_RESPOND_PARAMS_Windows", 40)]
    [InlineData("CK_X9_42_DH1_DERIVE_PARAMS_Windows", 28)]
    [InlineData("CK_X9_42_DH2_DERIVE_PARAMS_Windows", 48)]
    [InlineData("CK_X9_42_MQV_DERIVE_PARAMS_Windows", 52)]
    [InlineData("CK_XEDDSA_PARAMS_Windows", 4)]
    // END Windows InlineData
    public void WindowsSiblingStructSize(string typeName, int expectedSize)
    {
        var asm = typeof(CK_INFO).Assembly;
        var t = asm.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native." + typeName)
            ?? asm.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams." + typeName);
        Assert.NotNull(t);
        Assert.Equal(expectedSize, Marshal.SizeOf(t!));
    }

    /// <summary>
    /// The same Pack=1 siblings on 32-bit Windows (ILP32). CK_ULONG stays 4 bytes, but pointers
    /// shrink from 8 to 4, so every pointer-bearing struct is smaller here than on win-x64 while the
    /// pointer-free ones are byte-identical. CI runs a win-x86 leg; before these pins it had no
    /// absolute size expectations, because the win-x64 theory is gated to a 64-bit process.
    /// </summary>
    /// <remarks>
    /// These values are derived, not probed — no 32-bit Windows host was available. Each is the
    /// win-x64 pin minus 4 bytes per pointer field (counted recursively through nested structs).
    /// The derivation was validated first by reproducing all 98 win-x64 pins from the same field-walk
    /// with pointer = 8: it matched every one, so the pointer = 4 variant rests on a model already
    /// checked against known-good values rather than on arithmetic done by hand.
    /// </remarks>
    [ConditionalTheory(nameof(IsWindows32))]
    // BEGIN Windows x86 InlineData — OASIS Windows ILP32 ABI (CK_ULONG=4, ptr=4, pack=1)
    [InlineData("CK_AES_CBC_ENCRYPT_DATA_PARAMS_Windows", 24)]
    [InlineData("CK_AES_CTR_PARAMS_Windows", 20)]
    [InlineData("CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_Windows", 24)]
    [InlineData("CK_ASYNC_DATA_Windows", 20)]
    [InlineData("CK_ATTRIBUTE_Windows", 12)]
    [InlineData("CK_C_INITIALIZE_ARGS_Windows", 24)]
    [InlineData("CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_Windows", 24)]
    [InlineData("CK_CAMELLIA_CTR_PARAMS_Windows", 20)]
    [InlineData("CK_CCM_MESSAGE_PARAMS_Windows", 28)]
    [InlineData("CK_CCM_PARAMS_Windows", 24)]
    [InlineData("CK_CCM_WRAP_PARAMS_Windows", 32)]
    [InlineData("CK_CHACHA20_PARAMS_Windows", 16)]
    [InlineData("CK_CMS_SIG_PARAMS_Windows", 32)]
    [InlineData("CK_DERIVED_KEY_Windows", 12)]
    [InlineData("CK_DES_CBC_ENCRYPT_DATA_PARAMS_Windows", 16)]
    [InlineData("CK_DSA_PARAMETER_GEN_PARAM_Windows", 16)]
    [InlineData("CK_ECDH_AES_KEY_WRAP_PARAMS_Windows", 16)]
    [InlineData("CK_ECDH1_DERIVE_PARAMS_Windows", 20)]
    [InlineData("CK_ECDH2_DERIVE_PARAMS_Windows", 36)]
    [InlineData("CK_ECMQV_DERIVE_PARAMS_Windows", 40)]
    [InlineData("CK_EDDSA_PARAMS_Windows", 9)]
    [InlineData("CK_EXTRACT_PARAMS_Windows", 4)]
    [InlineData("CK_FUNCTION_LIST_3_0_Windows", 370)]
    [InlineData("CK_FUNCTION_LIST_3_2_Windows", 418)]
    [InlineData("CK_FUNCTION_LIST_Windows", 274)]
    [InlineData("CK_GCM_MESSAGE_PARAMS_Windows", 24)]
    [InlineData("CK_GCM_PARAMS_Windows", 24)]
    [InlineData("CK_GCM_WRAP_PARAMS_Windows", 28)]
    [InlineData("CK_GOSTR3410_DERIVE_PARAMS_Windows", 20)]
    [InlineData("CK_GOSTR3410_KEY_WRAP_PARAMS_Windows", 20)]
    [InlineData("CK_HASH_SIGN_ADDITIONAL_CONTEXT_Windows", 16)]
    [InlineData("CK_HKDF_PARAMS_Windows", 30)]
    [InlineData("CK_IKE_PRF_DERIVE_PARAMS_Windows", 26)]
    [InlineData("CK_IKE1_EXTENDED_DERIVE_PARAMS_Windows", 17)]
    [InlineData("CK_IKE1_PRF_DERIVE_PARAMS_Windows", 30)]
    [InlineData("CK_IKE2_PRF_PLUS_DERIVE_PARAMS_Windows", 17)]
    [InlineData("CK_INFO_Windows", 72)]
    [InlineData("CK_INTERFACE_Windows", 12)]
    [InlineData("CK_KEA_DERIVE_PARAMS_Windows", 21)]
    [InlineData("CK_KEY_DERIVATION_STRING_DATA_Windows", 8)]
    [InlineData("CK_KEY_WRAP_SET_OAEP_PARAMS_Windows", 9)]
    [InlineData("CK_KIP_PARAMS_Windows", 16)]
    [InlineData("CK_MAC_GENERAL_PARAMS_Windows", 4)]
    [InlineData("CK_MECHANISM_INFO_Windows", 12)]
    [InlineData("CK_MECHANISM_Windows", 12)]
    [InlineData("CK_OTP_PARAM_Windows", 12)]
    [InlineData("CK_OTP_PARAMS_Windows", 8)]
    [InlineData("CK_OTP_SIGNATURE_INFO_Windows", 8)]
    [InlineData("CK_PBE_PARAMS_Windows", 24)]
    [InlineData("CK_PKCS5_PBKD2_PARAMS_Windows", 36)]
    [InlineData("CK_PKCS5_PBKD2_PARAMS2_Windows", 36)]
    [InlineData("CK_PRF_DATA_PARAM_Windows", 12)]
    [InlineData("CK_RC2_CBC_PARAMS_Windows", 12)]
    [InlineData("CK_RC2_MAC_GENERAL_PARAMS_Windows", 8)]
    [InlineData("CK_RC2_PARAMS_Windows", 4)]
    [InlineData("CK_RC5_CBC_PARAMS_Windows", 16)]
    [InlineData("CK_RC5_MAC_GENERAL_PARAMS_Windows", 12)]
    [InlineData("CK_RC5_PARAMS_Windows", 8)]
    [InlineData("CK_RSA_AES_KEY_WRAP_PARAMS_Windows", 8)]
    [InlineData("CK_RSA_PKCS_OAEP_PARAMS_Windows", 20)]
    [InlineData("CK_RSA_PKCS_PSS_PARAMS_Windows", 12)]
    [InlineData("CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_Windows", 12)]
    [InlineData("CK_SALSA20_CHACHA20_POLY1305_PARAMS_Windows", 16)]
    [InlineData("CK_SALSA20_PARAMS_Windows", 12)]
    [InlineData("CK_SEED_CBC_ENCRYPT_DATA_PARAMS_Windows", 24)]
    [InlineData("CK_SESSION_INFO_Windows", 16)]
    [InlineData("CK_SIGN_ADDITIONAL_CONTEXT_Windows", 12)]
    [InlineData("CK_SKIPJACK_PRIVATE_WRAP_PARAMS_Windows", 44)]
    [InlineData("CK_SKIPJACK_RELAYX_PARAMS_Windows", 56)]
    [InlineData("CK_SLOT_INFO_Windows", 104)]
    [InlineData("CK_SP800_108_COUNTER_FORMAT_Windows", 5)]
    [InlineData("CK_SP800_108_DKM_LENGTH_FORMAT_Windows", 9)]
    [InlineData("CK_SP800_108_FEEDBACK_KDF_PARAMS_Windows", 28)]
    [InlineData("CK_SP800_108_KDF_PARAMS_Windows", 20)]
    [InlineData("CK_SSL3_KEY_MAT_OUT_Windows", 24)]
    [InlineData("CK_SSL3_KEY_MAT_PARAMS_Windows", 33)]
    [InlineData("CK_SSL3_MASTER_KEY_DERIVE_PARAMS_Windows", 20)]
    [InlineData("CK_SSL3_RANDOM_DATA_Windows", 16)]
    [InlineData("CK_TLS_KDF_PARAMS_Windows", 36)]
    [InlineData("CK_TLS_MAC_PARAMS_Windows", 12)]
    [InlineData("CK_TLS_PRF_PARAMS_Windows", 24)]
    [InlineData("CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS_Windows", 16)]
    [InlineData("CK_TLS12_KEY_MAT_PARAMS_Windows", 37)]
    [InlineData("CK_TLS12_MASTER_KEY_DERIVE_PARAMS_Windows", 24)]
    [InlineData("CK_TOKEN_INFO_Windows", 160)]
    [InlineData("CK_WTLS_KEY_MAT_OUT_Windows", 12)]
    [InlineData("CK_WTLS_KEY_MAT_PARAMS_Windows", 41)]
    [InlineData("CK_WTLS_MASTER_KEY_DERIVE_PARAMS_Windows", 24)]
    [InlineData("CK_WTLS_PRF_PARAMS_Windows", 28)]
    [InlineData("CK_WTLS_RANDOM_DATA_Windows", 16)]
    [InlineData("CK_X2RATCHET_INITIALIZE_PARAMS_Windows", 29)]
    [InlineData("CK_X2RATCHET_RESPOND_PARAMS_Windows", 29)]
    [InlineData("CK_X3DH_INITIATE_PARAMS_Windows", 28)]
    [InlineData("CK_X3DH_RESPOND_PARAMS_Windows", 24)]
    [InlineData("CK_X9_42_DH1_DERIVE_PARAMS_Windows", 20)]
    [InlineData("CK_X9_42_DH2_DERIVE_PARAMS_Windows", 36)]
    [InlineData("CK_X9_42_MQV_DERIVE_PARAMS_Windows", 40)]
    [InlineData("CK_XEDDSA_PARAMS_Windows", 4)]
    // END Windows x86 InlineData
    public void WindowsSiblingStructSize_OnX86(string typeName, int expectedSize)
    {
        var asm = typeof(CK_INFO).Assembly;
        var t = asm.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native." + typeName)
            ?? asm.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams." + typeName);
        Assert.NotNull(t);
        Assert.Equal(expectedSize, Marshal.SizeOf(t!));
    }

    /// <summary>
    /// Ties the win-x86 pins to the win-x64 pins by the one relationship that produces them: with
    /// Pack=1 there is no padding and CK_ULONG is 4 bytes on both Windows ABIs, so the only field
    /// that changes width is the pointer. Every x86 size must therefore be its x64 size minus 4 per
    /// pointer field, counted recursively through nested structs.
    /// </summary>
    /// <remarks>
    /// This runs on every platform, including Linux, where both Windows theories are skipped — so it
    /// is the only thing standing between a mistyped x86 literal and a red CI leg on hardware most
    /// contributors cannot reproduce. Note what it does and does not prove: it verifies the 98 x86
    /// literals are transcribed consistently with the 98 x64 literals under the stated model, not
    /// that the model matches the real ILP32 ABI. The win-x86 CI leg is what confirms the latter.
    /// </remarks>
    [Fact]
    public void WindowsX86Pins_AreDerivableFromTheX64Pins()
    {
        var x64 = PinnedSizes(nameof(WindowsSiblingStructSize));
        var x86 = PinnedSizes(nameof(WindowsSiblingStructSize_OnX86));

        Assert.NotEmpty(x64); // sanity: the attribute reflection actually found the rows
        Assert.Equal(x64.Count, x86.Count);

        var mismatches = new List<string>();
        foreach (var (name, x64Size) in x64)
        {
            if (!x86.TryGetValue(name, out int x86Size)) { mismatches.Add($"{name}: missing x86 row"); continue; }

            var t = typeof(CK_INFO).Assembly.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native." + name)
                 ?? typeof(CK_INFO).Assembly.GetType("KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams." + name);
            Assert.NotNull(t);

            int expected = x64Size - 4 * PointerFieldCount(t!);
            if (x86Size != expected) mismatches.Add($"{name}: x86 pinned {x86Size}, derived {expected} (x64 {x64Size})");
        }

        Assert.True(mismatches.Count == 0,
            "win-x86 pins are inconsistent with the win-x64 pins. Fix the x86 literal, or if the "
            + "struct genuinely changed shape, update both platforms' rows together: "
            + string.Join("; ", mismatches));
    }

    /// <summary>Reads the <c>[InlineData("Name", size)]</c> rows off one of the sibling-size theories.</summary>
    private static Dictionary<string, int> PinnedSizes(string methodName)
    {
        var method = typeof(MarshalSizeOfTests).GetMethod(methodName)!;
        var pins = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var attr in method.GetCustomAttributesData()
                     .Where(a => a.AttributeType.Name == "InlineDataAttribute"))
        {
            // InlineDataAttribute's ctor is (params object[] data).
            var args = (IReadOnlyList<CustomAttributeTypedArgument>)attr.ConstructorArguments[0].Value!;
            pins[(string)args[0].Value!] = (int)args[1].Value!;
        }
        return pins;
    }

    /// <summary>Counts pointer-width fields, recursing into nested structs. Inline buffers are byte
    /// arrays and <c>NativeCULong</c> is 4 bytes on both Windows ABIs, so neither contributes.</summary>
    private static int PointerFieldCount(Type t)
    {
        if (t == typeof(IntPtr) || t == typeof(UIntPtr)) return 1;
        if (t.Name == "NativeCULong" || t.IsPrimitive || t.IsEnum) return 0;
        if (t.GetCustomAttributes().Any(a => a.GetType().Name == "InlineArrayAttribute")) return 0;
        if (!t.IsValueType) return 0;
        return t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .Sum(f => PointerFieldCount(f.FieldType));
    }
}
