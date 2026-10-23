using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>TripleDESPkcs11Tests over BouncyHsm — thin wrapper over <see cref="TripleDESPkcs11TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class TripleDESPkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ctor_NonDes3Key_Throws() => TripleDESPkcs11TestCases.Assert_Ctor_NonDes3Key_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => TripleDESPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeySize_ReflectsTokenKeyLength() => TripleDESPkcs11TestCases.Assert_KeySize_ReflectsTokenKeyLength(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => TripleDESPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Cfb_NotSupported() => TripleDESPkcs11TestCases.Assert_Cfb_NotSupported(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => TripleDESPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Cbc_EmptyInput_MatchesBcl() => TripleDESPkcs11TestCases.Assert_Cbc_EmptyInput_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable() => TripleDESPkcs11TestCases.Assert_DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => TripleDESPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector() => TripleDESPkcs11TestCases.Assert_TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector(_backend);
}
