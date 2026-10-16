using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RC2Pkcs11Tests over SoftHsm — thin wrapper over <see cref="RC2Pkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class RC2Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Ctor_NonRc2Key_Throws() => RC2Pkcs11TestCases.Assert_Ctor_NonRc2Key_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => RC2Pkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => RC2Pkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
