using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

public sealed class WrapHardeningAttributeTests
{
    [Fact]
    public void SecretKey_WrapWithTrusted_And_Trusted()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapWithTrusted()
            .Trusted()
            .Build();

        Assert.True(template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_WITH_TRUSTED).GetValueAsBool());
        Assert.True(template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_TRUSTED).GetValueAsBool());
    }

    [Fact]
    public void PrivateKey_WrapWithTrusted()
    {
        using ObjectTemplate template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .WrapWithTrusted()
            .Build();

        Assert.True(template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_WITH_TRUSTED).GetValueAsBool());
    }

    [Fact]
    public void PublicKey_Trusted()
    {
        using ObjectTemplate template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Trusted()
            .Build();

        Assert.True(template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_TRUSTED).GetValueAsBool());
    }

    [Fact]
    public void WrapWithTrusted_CanBeSetFalseExplicitly()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .WrapWithTrusted(false)
            .Build();

        Assert.False(template.Attributes.Single(a => a.Type == (ulong)CKA.CKA_WRAP_WITH_TRUSTED).GetValueAsBool());
    }
}
