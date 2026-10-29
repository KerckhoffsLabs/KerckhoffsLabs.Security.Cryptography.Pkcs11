using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

[Collection("WolfPkcs11")]
public sealed class InsecureOperationGateTests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Encrypt_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Encrypt_InsecureMechanismThrows(_backend, mech);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Encrypt_AllowInsecure_BypassesGate()
        => InsecureOperationGateTestCases.Assert_Encrypt_AllowInsecureBypassesGate(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Decrypt_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Decrypt_InsecureMechanismThrows(_backend, mech);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Decrypt_AllowInsecure_BypassesGate()
        => InsecureOperationGateTestCases.Assert_Decrypt_AllowInsecureBypassesGate(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    public void Sign_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
}
