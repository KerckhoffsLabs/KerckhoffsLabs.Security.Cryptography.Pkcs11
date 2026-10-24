using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyCapabilityEnforcement over tpm2-pkcs11 — thin wrapper over <see cref="KeyCapabilityEnforcementTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class KeyCapabilityEnforcementTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Sign_WithSignFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Sign_WithSignFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Verify_WithVerifyFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Verify_WithVerifyFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_WithEncryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Encrypt_WithEncryptFalse_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Decrypt_WithDecryptFalse_Throws() => KeyCapabilityEnforcementTestCases.Assert_Decrypt_WithDecryptFalse_Throws(_backend);
}
