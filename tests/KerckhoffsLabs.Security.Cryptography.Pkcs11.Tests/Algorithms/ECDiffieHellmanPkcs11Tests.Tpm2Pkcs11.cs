using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDiffieHellmanPkcs11Tests over tpm2-pkcs11 — thin wrapper over <see cref="ECDiffieHellmanPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class ECDiffieHellmanPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void Ctor_NonEcKey_Throws() => ECDiffieHellmanPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyFromHash_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyFromHmac_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveRawSecretAgreement_MatchesBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveRawSecretAgreement_P521_MatchesBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_P521_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyMaterial_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyMaterial_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void PublicKey_ExportsTokenPoint() => ECDiffieHellmanPkcs11TestCases.Assert_PublicKey_ExportsTokenPoint(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void DeriveKeyTls_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyTls_NotSupported(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void ExportParameters_Private_ThrowsInsecure() => ECDiffieHellmanPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    public void ImportParameters_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#663: CKA_DERIVE is not mapped, so an ECDH key pair is refused")]
    [InlineData("P-256")]
    [InlineData("P-384")]
    public void DeriveRawSecretAgreement_PeerXLooksLikeADerLength_MatchesBcl(string curve)
        => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_PeerXLooksLikeADerLength_MatchesBcl(_backend, curve);
}
