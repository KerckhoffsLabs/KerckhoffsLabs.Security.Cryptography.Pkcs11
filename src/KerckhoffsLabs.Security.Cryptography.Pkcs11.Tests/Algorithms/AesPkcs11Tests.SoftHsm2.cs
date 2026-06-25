using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesPkcs11 over SoftHsm2 — thin wrapper over <see cref="AesPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class AesPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonAesKey_Throws() => AesPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_Cfb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_WithAllowInsecure_GateBypassed() => AesPkcs11TestCases.Assert_Cfb_WithAllowInsecure_GateBypassed(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_NonNonePadding_Throws() => AesPkcs11TestCases.Assert_Cfb_NonNonePadding_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => AesPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => AesPkcs11TestCases.Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => AesPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(16, 128)]
    [InlineData(32, 256)]
    public void KeySize_ReflectsTokenKeyLength(int keyBytes, int expectedBits)
        => AesPkcs11TestCases.Assert_KeySize_ReflectsTokenKeyLength(_backend, keyBytes, expectedBits);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => AesPkcs11TestCases.Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => AesPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
