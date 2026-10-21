using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// <see cref="CKD.CKD_NULL"/> on ECDH keeps the raw shared secret Z. The default policies refuse it into
/// a working key (SP 800-56A forbids using Z directly) and allow it only into a derivation-only secret,
/// which the session recognises from the derive template: <c>Pkcs11SessionCore.IsDerivationOnlySecret</c>.
/// </summary>
public sealed class DerivationOnlySecretTests
{
    private static SecretKeyTemplateBuilder DerivationOnly() => ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
        .ValueLen(32).Derive()
        .Encrypt(false).Decrypt(false).Sign(false).Verify(false).Wrap(false).Unwrap(false);

    private static bool Matches(SecretKeyTemplateBuilder builder)
    {
        using ObjectTemplate template = builder.Build();
        return Pkcs11SessionCore.IsDerivationOnlySecret([.. template.Attributes]);
    }

    [Fact]
    public void DeriveOnlyGenericSecret_Matches() => Assert.True(Matches(DerivationOnly()));

    [Fact]
    public void ExplicitSensitiveNonExtractable_Matches() => Assert.True(Matches(DerivationOnly().Sensitive().NonExtractable()));

    [Theory]
    [InlineData(CKA.CKA_ENCRYPT)]
    [InlineData(CKA.CKA_DECRYPT)]
    [InlineData(CKA.CKA_SIGN)]
    [InlineData(CKA.CKA_VERIFY)]
    [InlineData(CKA.CKA_WRAP)]
    [InlineData(CKA.CKA_UNWRAP)]
    public void AUsageAllowed_DoesNotMatch(CKA usage) => Assert.False(Matches(DerivationOnly().Attribute(usage, true)));

    // An omitted usage attribute takes the token's default, which may be true; an omitted class, key
    // type or CKA_DERIVE leaves the object undescribed. The builder always writes every one of them, so
    // the omission is made by hand.
    [Theory]
    [InlineData(CKA.CKA_CLASS)]
    [InlineData(CKA.CKA_KEY_TYPE)]
    [InlineData(CKA.CKA_DERIVE)]
    [InlineData(CKA.CKA_ENCRYPT)]
    [InlineData(CKA.CKA_DECRYPT)]
    [InlineData(CKA.CKA_SIGN)]
    [InlineData(CKA.CKA_VERIFY)]
    [InlineData(CKA.CKA_WRAP)]
    [InlineData(CKA.CKA_UNWRAP)]
    public void ARequiredAttributeOmitted_DoesNotMatch(CKA required)
    {
        using ObjectTemplate template = DerivationOnly().Build();
        Assert.False(Pkcs11SessionCore.IsDerivationOnlySecret([.. template.Attributes.Where(a => a.Type != required)]));
    }

    // The session's secure defaults fill these in (CKA_SENSITIVE=true, CKA_EXTRACTABLE=false), so
    // leaving them out still describes a derivation-only secret.
    [Theory]
    [InlineData(CKA.CKA_SENSITIVE)]
    [InlineData(CKA.CKA_EXTRACTABLE)]
    public void SensitiveOrExtractableOmitted_StillMatches(CKA omitted)
    {
        using ObjectTemplate template = DerivationOnly().Build();
        Assert.True(Pkcs11SessionCore.IsDerivationOnlySecret([.. template.Attributes.Where(a => a.Type != omitted)]));
    }

    [Fact]
    public void NotDerivable_DoesNotMatch() => Assert.False(Matches(DerivationOnly().Derive(false)));

    [Fact]
    public void AesKey_DoesNotMatch()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32).Derive().Encrypt(false).Decrypt(false).Sign(false).Verify(false).Wrap(false).Unwrap(false)
            .Build();
        Assert.False(Pkcs11SessionCore.IsDerivationOnlySecret([.. template.Attributes]));
    }

    [Fact]
    public void NonSensitive_DoesNotMatch() => Assert.False(Matches(DerivationOnly().Sensitive(false)));

    [Fact]
    public void Extractable_DoesNotMatch() => Assert.False(Matches(DerivationOnly().Extractable()));

    // ---- The rule in the default policies ----------------------------------------------------------

    public static TheoryData<string> DefaultPolicies => ["SecureOnly", "FipsOnly"];

    private static ICryptoPolicy Policy(string name) => name == "FipsOnly" ? CryptoPolicy.FipsOnly : CryptoPolicy.SecureOnly;

    [Theory]
    [MemberData(nameof(DefaultPolicies))]
    public void CkdNull_IntoADerivationOnlySecret_IsAllowed(string policy)
        => Assert.True(Policy(policy).Evaluate(
            new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL) { ResultIsDerivationOnlySecret = true }).IsAllowed);

    [Theory]
    [MemberData(nameof(DefaultPolicies))]
    public void CkdNull_IntoAnyOtherObject_IsRefused(string policy)
        => Assert.False(Policy(policy).Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)).IsAllowed);

    // The flag widens CKD_NULL only: a KDF the policy refuses stays refused.
    [Theory]
    [MemberData(nameof(DefaultPolicies))]
    public void RefusedKdf_IntoADerivationOnlySecret_IsStillRefused(string policy)
        => Assert.False(Policy(policy).Evaluate(
            new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF) { ResultIsDerivationOnlySecret = true }).IsAllowed);
}
