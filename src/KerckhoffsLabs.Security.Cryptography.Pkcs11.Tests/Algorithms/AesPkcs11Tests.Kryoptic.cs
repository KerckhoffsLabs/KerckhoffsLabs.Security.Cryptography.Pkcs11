using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesPkcs11 over Kryoptic — thin wrapper over <see cref="AesPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class AesPkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonAesKey_Throws() => AesPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => AesPkcs11TestCases.Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Cfb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_Cfb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Cfb_WithAllowInsecure_GateBypassed() => AesPkcs11TestCases.Assert_Cfb_WithAllowInsecure_GateBypassed(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Cfb_NonNonePadding_Throws() => AesPkcs11TestCases.Assert_Cfb_NonNonePadding_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => AesPkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => AesPkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => AesPkcs11TestCases.Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => AesPkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(16, 128)]
    [InlineData(32, 256)]
    public void KeySize_ReflectsTokenKeyLength(int keyBytes, int expectedBits)
        => AesPkcs11TestCases.Assert_KeySize_ReflectsTokenKeyLength(_backend, keyBytes, expectedBits);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => AesPkcs11TestCases.Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => AesPkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
