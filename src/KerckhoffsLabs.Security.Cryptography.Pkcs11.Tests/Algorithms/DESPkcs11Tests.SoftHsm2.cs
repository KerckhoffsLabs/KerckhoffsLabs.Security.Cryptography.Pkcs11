using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DESPkcs11Tests over SoftHsm — thin wrapper over <see cref="DESPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class DESPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonDesKey_Throws() => DESPkcs11TestCases.Assert_Ctor_NonDesKey_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => DESPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => DESPkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => DESPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_NotSupported() => DESPkcs11TestCases.Assert_Cfb_NotSupported(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => DESPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => DESPkcs11TestCases.Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => DESPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
