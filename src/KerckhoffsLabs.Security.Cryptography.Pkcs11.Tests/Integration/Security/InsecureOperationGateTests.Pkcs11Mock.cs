using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// Insecure-mechanism gate tests against pkcs11-mock.
/// All tests run unconditionally: <c>InsecureOperationException</c> is thrown (or
/// bypassed) in managed code before any P/Invoke call, so no real hardware or crypto is
/// required.
/// </summary>
[Collection("Mock")]
public sealed class InsecureOperationGateTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    // --- Encrypt gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_AES_CBC)]   // raw (unauthenticated) AES-CBC
    [InlineData((ulong)CKM.CKM_AES_CTR)]   // unauthenticated AES-CTR
    [InlineData((ulong)CKM.CKM_RC4)]       // broken stream cipher
    [InlineData((ulong)CKM.CKM_RC2_CBC)]   // deprecated cipher
    [InlineData((ulong)CKM.CKM_SEED_CBC)]  // legacy cipher
    [InlineData((ulong)CKM.CKM_CAST128_CBC)]      // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_RC5_CBC)]        // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_BLOWFISH_CBC)]   // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_SKIPJACK_CBC64)] // withdrawn cipher
    public void Encrypt_InsecureMechanismThrows_Mock(ulong mech)
        => InsecureOperationGateTestCases.Assert_Encrypt_InsecureMechanismThrows(_backend, mech);

    [Fact]
    public void Encrypt_AllowInsecure_BypassesGate_Mock()
        => InsecureOperationGateTestCases.Assert_Encrypt_AllowInsecureBypassesGate(_backend);

    // --- Decrypt gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Decrypt_InsecureMechanismThrows_Mock(ulong mech)
        => InsecureOperationGateTestCases.Assert_Decrypt_InsecureMechanismThrows(_backend, mech);

    [Fact]
    public void Decrypt_AllowInsecure_BypassesGate_Mock()
        => InsecureOperationGateTestCases.Assert_Decrypt_AllowInsecureBypassesGate(_backend);

    // --- Sign gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    [InlineData((ulong)CKM.CKM_ECDSA_SHA1)]  // SHA-1 in signatures
    [InlineData((ulong)CKM.CKM_SHA_1_HMAC)]  // SHA-1 in MACs
    [InlineData((ulong)CKM.CKM_RSA_X_509)]   // raw RSA, no padding
    public void Sign_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    // --- Verify gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);

    // --- Strong-hash RSA PKCS#1 v1.5 signatures are NOT gated ---

    [Theory]
    [InlineData((ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void Sign_StrongHashV15_NotGated(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_MechanismNotGated(_backend, mech);

    [Theory]
    [InlineData((ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void Verify_StrongHashV15_NotGated(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_MechanismNotGated(_backend, mech);

    // --- Digest gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    [InlineData((ulong)CKM.CKM_MD2)]        // broken hash
    [InlineData((ulong)CKM.CKM_RIPEMD160)]  // deprecated hash
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);

    // --- GenerateKey gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_RC4_KEY_GEN)]   // broken cipher key-gen
    [InlineData((ulong)CKM.CKM_RC2_KEY_GEN)]   // deprecated cipher key-gen
    [InlineData((ulong)CKM.CKM_SEED_KEY_GEN)]  // legacy cipher key-gen
    [InlineData((ulong)CKM.CKM_CAST128_KEY_GEN)]    // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_RC5_KEY_GEN)]      // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_BLOWFISH_KEY_GEN)] // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_SKIPJACK_KEY_GEN)] // withdrawn cipher
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    // --- DeriveKey gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
}
