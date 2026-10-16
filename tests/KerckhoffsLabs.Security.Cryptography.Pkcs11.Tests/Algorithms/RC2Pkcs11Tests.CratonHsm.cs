using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RC2Pkcs11Tests over Craton HSM — thin wrapper over <see cref="RC2Pkcs11TestCases"/>.</summary>
[Collection("CratonHsm")]
[ResetCratonHsmLogin]
public sealed class RC2Pkcs11Tests_CratonHsm(CratonHsmBackendFixture f)
{
    private readonly CratonHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_NonRc2Key_Throws() => RC2Pkcs11TestCases.Assert_Ctor_NonRc2Key_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => RC2Pkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => RC2Pkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
