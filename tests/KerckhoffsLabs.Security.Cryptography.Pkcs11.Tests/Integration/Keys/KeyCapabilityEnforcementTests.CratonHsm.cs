using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyCapabilityEnforcement over Craton HSM — thin wrapper over <see cref="KeyCapabilityEnforcementTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class KeyCapabilityEnforcementTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Sign_WithSignFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Sign_WithSignFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Verify_WithVerifyFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Verify_WithVerifyFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Encrypt_WithEncryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Encrypt_WithEncryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_WithDecryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Decrypt_WithDecryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignRecover_WithSignRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: true);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void VerifyRecover_WithVerifyRecoverFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(_backend, sign: false);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(KeyCapabilityEnforcementTestCases.DeriveMechanisms), MemberType = typeof(KeyCapabilityEnforcementTestCases))]
    public void Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(string derivation) => KeyCapabilityEnforcementTestCases.Assert_Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(_backend, derivation);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Encapsulate_WithEncapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: true);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decapsulate_WithDecapsulateFalse_IsKeyFunctionNotPermitted() => KeyCapabilityEnforcementTestCases.Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(_backend, encapsulate: false);
}
