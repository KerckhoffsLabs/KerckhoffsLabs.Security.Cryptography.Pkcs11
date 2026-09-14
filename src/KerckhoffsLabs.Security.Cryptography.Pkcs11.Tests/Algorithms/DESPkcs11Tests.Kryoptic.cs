using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DESPkcs11Tests over Kryoptic — thin wrapper over <see cref="DESPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class DESPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NonDesKey_Throws() => DESPkcs11TestCases.Assert_Ctor_NonDesKey_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Cfb_NotSupported() => DESPkcs11TestCases.Assert_Cfb_NotSupported(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => DESPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => DESPkcs11TestCases.Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => DESPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
