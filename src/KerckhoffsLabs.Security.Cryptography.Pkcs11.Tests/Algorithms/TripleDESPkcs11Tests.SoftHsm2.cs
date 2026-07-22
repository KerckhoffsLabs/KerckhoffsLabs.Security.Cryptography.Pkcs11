using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>TripleDESPkcs11Tests over SoftHsm — thin wrapper over <see cref="TripleDESPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class TripleDESPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonDes3Key_Throws() => TripleDESPkcs11TestCases.Assert_Ctor_NonDes3Key_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => TripleDESPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => TripleDESPkcs11TestCases.Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void KeySize_ReflectsTokenKeyLength() => TripleDESPkcs11TestCases.Assert_KeySize_ReflectsTokenKeyLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => TripleDESPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_NotSupported() => TripleDESPkcs11TestCases.Assert_Cfb_NotSupported(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => TripleDESPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => TripleDESPkcs11TestCases.Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => TripleDESPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector() => TripleDESPkcs11TestCases.Assert_TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector(_backend);
}
