using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

[Collection("SoftHsm")]
public sealed class InsecureOperationGateTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // --- Encrypt gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Encrypt_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Encrypt_InsecureMechanismThrows(_backend, mech);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_AllowInsecure_BypassesGate_SoftHsm()
        => InsecureOperationGateTestCases.Assert_Encrypt_AllowInsecureBypassesGate(_backend);

    // --- Decrypt gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Decrypt_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Decrypt_InsecureMechanismThrows(_backend, mech);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_AllowInsecure_BypassesGate_SoftHsm()
        => InsecureOperationGateTestCases.Assert_Decrypt_AllowInsecureBypassesGate(_backend);

    // --- Sign gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    public void Sign_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    // --- Verify gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);

    // --- Digest gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);

    // --- GenerateKey gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    // --- DeriveKey gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
}
