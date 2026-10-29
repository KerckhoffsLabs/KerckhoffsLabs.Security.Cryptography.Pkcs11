using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyCapabilityEnforcement over Kryoptic — thin wrapper over <see cref="KeyCapabilityEnforcementTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class KeyCapabilityEnforcementTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.MacKeyUsageRefusalAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Kryoptic refuses an HMAC key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Sign_WithSignFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Sign_WithSignFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.MacKeyUsageRefusalAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Kryoptic refuses an HMAC key without the usage with CKR_KEY_TYPE_INCONSISTENT")]
    public void Verify_WithVerifyFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Verify_WithVerifyFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_WithEncryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Encrypt_WithEncryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_WithDecryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Decrypt_WithDecryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignRecover_WithSignRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: true);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyRecover_WithVerifyRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: false);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(KeyCapabilityEnforcementTestCases.DeriveMechanisms), MemberType = typeof(KeyCapabilityEnforcementTestCases))]
    public void Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(string derivation) => KeyCapabilityEnforcementTestCases.Assert_Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(_backend, derivation);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encapsulate_WithEncapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: true);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decapsulate_WithDecapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: false);
}
