using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RC2Pkcs11Tests over OpenCryptoki — thin wrapper over <see cref="RC2Pkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class RC2Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NonRc2Key_Throws() => RC2Pkcs11TestCases.Assert_Ctor_NonRc2Key_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => RC2Pkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => RC2Pkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
