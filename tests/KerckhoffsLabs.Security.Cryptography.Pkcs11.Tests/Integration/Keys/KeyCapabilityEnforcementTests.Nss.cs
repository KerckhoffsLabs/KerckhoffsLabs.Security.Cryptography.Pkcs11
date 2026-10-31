using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyCapabilityEnforcement over NSS — thin wrapper over <see cref="KeyCapabilityEnforcementTestCases"/>.</summary>
[Collection("Nss")]
public sealed class KeyCapabilityEnforcementTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.KeyUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS softoken refuses a key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Sign_WithSignFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Sign_WithSignFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.KeyUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS softoken refuses a key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Verify_WithVerifyFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Verify_WithVerifyFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.KeyUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS softoken refuses a key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Encrypt_WithEncryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Encrypt_WithEncryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.KeyUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS softoken refuses a key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Decrypt_WithDecryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Decrypt_WithDecryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.SignRecoverUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS signs with recovery under a key whose CKA_SIGN_RECOVER is FALSE")]
    public void SignRecover_WithSignRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: true);

    [Fact(SkipUnless = nameof(NssBackendFixture.KeyUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS softoken refuses a key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void VerifyRecover_WithVerifyRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: false);

    [Theory(SkipUnless = nameof(NssBackendFixture.DeriveUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS derives from a key whose CKA_DERIVE is FALSE")]
    [MemberData(nameof(KeyCapabilityEnforcementTestCases.DeriveMechanisms), MemberType = typeof(KeyCapabilityEnforcementTestCases))]
    public void Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(string derivation) => KeyCapabilityEnforcementTestCases.Assert_Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(_backend, derivation);

    [Fact(SkipUnless = nameof(NssBackendFixture.KemUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS encapsulates and decapsulates under keys without the usage")]
    public void Encapsulate_WithEncapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: true);

    [Fact(SkipUnless = nameof(NssBackendFixture.KemUsageRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS encapsulates and decapsulates under keys without the usage")]
    public void Decapsulate_WithDecapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: false);
}
