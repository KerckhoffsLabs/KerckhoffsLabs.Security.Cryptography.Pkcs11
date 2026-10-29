using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDiffieHellmanPkcs11Tests over wolfPKCS11 — thin wrapper over <see cref="ECDiffieHellmanPkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class ECDiffieHellmanPkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ctor_NonEcKey_Throws() => ECDiffieHellmanPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKeyFromHash_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKeyFromHmac_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveRawSecretAgreement_MatchesBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveRawSecretAgreement_P521_MatchesBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_P521_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKeyMaterial_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyMaterial_AgreesWithBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void PublicKey_ExportsTokenPoint() => ECDiffieHellmanPkcs11TestCases.Assert_PublicKey_ExportsTokenPoint(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DeriveKeyTls_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyTls_NotSupported(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDiffieHellmanPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ImportParameters_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    [InlineData("P-256")]
    [InlineData("P-384")]
    public void DeriveRawSecretAgreement_PeerXLooksLikeADerLength_MatchesBcl(string curve)
        => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_PeerXLooksLikeADerLength_MatchesBcl(_backend, curve);
}
