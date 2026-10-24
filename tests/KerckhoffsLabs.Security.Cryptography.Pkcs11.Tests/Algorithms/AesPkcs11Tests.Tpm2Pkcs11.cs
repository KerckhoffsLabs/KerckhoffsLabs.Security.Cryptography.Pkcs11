using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="AesPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class AesPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ctor_NonAesKey_Throws() => AesPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Cfb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_Cfb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Cfb_WithAllowInsecure_GateBypassed() => AesPkcs11TestCases.Assert_Cfb_WithAllowInsecure_GateBypassed(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Cfb_NonNonePadding_Throws() => AesPkcs11TestCases.Assert_Cfb_NonNonePadding_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    [InlineData(8)]
    [InlineData(128)]
    public void Cfb_OneShots_MatchBclAtEveryLength(int feedbackSizeInBits) => AesPkcs11TestCases.Assert_Cfb_OneShots_MatchBclAtEveryLength(_backend, feedbackSizeInBits);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Cfb128_PartialSegment_ThrowsLikeBcl() => AesPkcs11TestCases.Assert_Cfb128_PartialSegment_ThrowsLikeBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptCbc_UnsupportedPadding_Throws() => AesPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptEcb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => AesPkcs11TestCases.Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void KeyWrapPadded_UsesTheTokensKwp_AndMatchesBcl() => AesPkcs11TestCases.Assert_KeyWrapPadded_UsesTheTokensKwp_AndMatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void GenerateIV_ProducesBlockSizedIv() => AesPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    [InlineData(16, 128)]
    [InlineData(32, 256)]
    public void KeySize_ReflectsTokenKeyLength(int keyBytes, int expectedBits)
        => AesPkcs11TestCases.Assert_KeySize_ReflectsTokenKeyLength(_backend, keyBytes, expectedBits);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Cbc_EmptyInput_MatchesBcl() => AesPkcs11TestCases.Assert_Cbc_EmptyInput_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable() => AesPkcs11TestCases.Assert_DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => AesPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
