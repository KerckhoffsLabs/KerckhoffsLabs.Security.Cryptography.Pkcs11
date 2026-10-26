using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDsaPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="ECDsaPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class ECDsaPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    [InlineData("P-256", "SHA256")]
    [InlineData("P-256", "SHA384")]
    [InlineData("P-256", "SHA512")]
    [InlineData("P-384", "SHA256")]
    [InlineData("P-384", "SHA384")]
    [InlineData("P-384", "SHA512")]
    [InlineData("P-521", "SHA256")]
    [InlineData("P-521", "SHA384")]
    [InlineData("P-521", "SHA512")]
    public void SignVerifyData_CurveHashMatrix_RoundTrips(string curve, string hashName)
    {
        _backend.SkipUnlessTpmImplementsSha512(curve == "P-521" && hashName == "SHA512");
        ECDsaPkcs11TestCases.Assert_SignVerifyData_CurveHashMatrix_RoundTrips(_backend, curve, hashName);
    }

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void TrySignData_Span_VerifyData_Span_RoundTrips(string curve)
    {
        // P-521 signs with SHA-512
        _backend.SkipUnlessTpmImplementsSha512(curve == "P-521");
        ECDsaPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend, curve);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void TrySignData_Sha224_UnderAllowInsecure_RoundTrips() => ECDsaPkcs11TestCases.Assert_TrySignData_Sha224_UnderAllowInsecure_RoundTrips(_backend, "P-256");

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void TrySignData_Sha224_WithoutAllowInsecure_Throws() => ECDsaPkcs11TestCases.Assert_TrySignData_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve) => ECDsaPkcs11TestCases.Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(_backend, curve);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve)
    {
        // P-521 signs with SHA-512
        _backend.SkipUnlessTpmImplementsSha512(curve == "P-521");
        ECDsaPkcs11TestCases.Assert_SignData_VerifiesUnderBclFromExportedPublicKey(_backend, curve);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void Ctor_NonEcKey_Throws() => ECDsaPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void VerifyData_SignatureOfTheWrongLength_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_VerifyData_SignatureOfTheWrongLength_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void SignHash_VerifyHash_RoundTrips() => ECDsaPkcs11TestCases.Assert_SignHash_VerifyHash_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void SignHash_NullHash_Throws() => ECDsaPkcs11TestCases.Assert_SignHash_NullHash_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void VerifyHash_NullArguments_Throw() => ECDsaPkcs11TestCases.Assert_VerifyHash_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void ExportParameters_Private_ThrowsInsecure() => ECDsaPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void ExportExplicitParameters_Throws() => ECDsaPkcs11TestCases.Assert_ExportExplicitParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void ImportParameters_Throws() => ECDsaPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void GenerateKey_Throws() => ECDsaPkcs11TestCases.Assert_GenerateKey_Throws(_backend);
}
