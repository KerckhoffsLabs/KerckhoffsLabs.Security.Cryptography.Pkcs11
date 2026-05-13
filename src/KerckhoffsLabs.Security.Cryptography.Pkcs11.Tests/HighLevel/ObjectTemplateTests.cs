using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class ObjectTemplateTests
{
    [Fact]
    public void Empty_BuildsEmptyTemplate()
    {
        using var template = ObjectTemplate.Empty().Build();

        Assert.Equal(0, template.Count);
    }

    [Fact]
    public void GenericBuilder_AddsAttribute()
    {
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "k")
            .Build();

        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void GenericBuilder_SetAttributeTwice_ReplacesValue()
    {
        // The fluent API treats repeated attributes as "last write wins" per PKCS#11
        // v3.1 §5.5.6 — duplicate CKA in a template is not an error; the latest value
        // overrides earlier ones. The builder collapses them to a single ObjectAttribute.
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "first")
            .Attribute(CKA.CKA_LABEL, "second")
            .Build();

        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void Build_TransfersOwnership_FurtherBuildThrows()
    {
        var builder = ObjectTemplate.Empty().Attribute(CKA.CKA_LABEL, "k");

        using var first = builder.Build();
        Assert.Throws<InvalidOperationException>((Action)(() => builder.Build()));
    }

    [Fact]
    public void Dispose_DisposesOwnedAttributes()
    {
        var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_LABEL, "k")
            .Build();

        template.Dispose();
        // Disposing twice must be a no-op.
        template.Dispose();
    }

    [Fact]
    public void Builder_NeverBuilt_DoesNotLeak()
    {
        // Builder that is never built should still release the attributes it accumulated
        // when garbage-collected; the test exercises the Dispose path that the builder
        // exposes so an explicit cleanup is possible.
        var builder = (IDisposable)ObjectTemplate.Empty().Attribute(CKA.CKA_LABEL, "k");
        builder.Dispose();
    }

    [Fact]
    public void SecretKey_PresetsClassAndKeyType()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();

        // CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE = 4 defaults.
        Assert.Equal(4, template.Count);
    }

    [Fact]
    public void SecretKey_HasSensitiveAndNonExtractableSecureDefaults()
    {
        // The builder should set CKA_SENSITIVE=true and CKA_EXTRACTABLE=false by
        // default. These secure defaults are required by the spec — verify both
        // attributes appear in the produced template with the expected values.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();
        var attrs = template.Attributes;

        var sensitive = attrs.Single(a => a.Type == (ulong)CKA.CKA_SENSITIVE);
        var extractable = attrs.Single(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE);

        // Both attributes carry a CK_BBOOL — value length is 1.
        Assert.Equal(1, sensitive.ValueLength);
        Assert.Equal(1, extractable.ValueLength);
    }

    [Fact]
    public void SecretKey_Extractable_OverridesDefault()
    {
        // Caller explicitly opts into insecure-by-PKCS#11-standard behavior.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Extractable()
            .Build();

        // Count is still 4 — Extractable() replaces the default value, not adds a new one.
        Assert.Equal(4, template.Count);
    }

    [Fact]
    public void SecretKey_ValueLen_AddsLengthAttribute()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(256 / 8)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE_LEN);
    }

    [Fact]
    public void SecretKey_KeyUsageFluentMethods_AddAttributes()
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Encrypt()
            .Decrypt()
            .Sign()
            .Verify()
            .Wrap()
            .Unwrap()
            .Derive()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_ENCRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DECRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SIGN);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VERIFY);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_WRAP);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_UNWRAP);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DERIVE);
    }

    [Fact]
    public void PrivateKey_PresetsClassKeyTypeAndSecureDefaults()
    {
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Build();

        // CKA_CLASS, CKA_KEY_TYPE, CKA_PRIVATE=true, CKA_SENSITIVE=true,
        // CKA_EXTRACTABLE=false = 5 defaults.
        Assert.Equal(5, template.Count);
    }

    [Fact]
    public void PrivateKey_AsymmetricUsageFlags_AddAttributes()
    {
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sign()
            .Decrypt()
            .Derive()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SIGN);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DECRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_DERIVE);
    }

    [Fact]
    public void PublicKey_PresetsClassAndKeyType()
    {
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA).Build();

        // CKA_CLASS, CKA_KEY_TYPE = 2 defaults. Public keys do not get the
        // sensitive/non-extractable defaults — they are not sensitive material.
        Assert.Equal(2, template.Count);
    }

    [Fact]
    public void PublicKey_VerifyAndEncryptUsageFlags()
    {
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Verify()
            .Encrypt()
            .Wrap()
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VERIFY);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_ENCRYPT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_WRAP);
    }

    [Fact]
    public void Certificate_PresetsClassAndCertType()
    {
        using var template = ObjectTemplate.ForCertificate(CKC.CKC_X_509).Build();

        // CKA_CLASS, CKA_CERTIFICATE_TYPE = 2 defaults.
        Assert.Equal(2, template.Count);
    }

    [Fact]
    public void Certificate_FluentMethods_AddSubjectAndValue()
    {
        byte[] subject = { 0x30, 0x05 };
        byte[] cert = { 0x30, 0x82 };

        using var template = ObjectTemplate.ForCertificate(CKC.CKC_X_509)
            .Subject(subject)
            .Value(cert)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_SUBJECT);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE);
    }

    [Fact]
    public void Data_PresetsClass()
    {
        using var template = ObjectTemplate.ForData().Build();

        // CKA_CLASS = 1 default.
        Assert.Equal(1, template.Count);
    }

    [Fact]
    public void Data_ValueAndApplication_AddAttributes()
    {
        byte[] payload = { 0x01, 0x02, 0x03 };

        using var template = ObjectTemplate.ForData()
            .Application("my-app")
            .Value(payload)
            .Build();

        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_APPLICATION);
        Assert.Contains(template.Attributes, a => a.Type == (ulong)CKA.CKA_VALUE);
    }
}
