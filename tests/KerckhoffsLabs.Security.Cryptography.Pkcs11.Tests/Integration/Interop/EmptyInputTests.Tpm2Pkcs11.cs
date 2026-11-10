using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>EmptyInput over tpm2-pkcs11 — thin wrapper over <see cref="EmptyInputTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class EmptyInputTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Sha256_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Hmac_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(_backend);
}
