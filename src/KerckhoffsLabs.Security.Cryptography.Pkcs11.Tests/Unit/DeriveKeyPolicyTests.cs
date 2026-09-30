using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Every key a derivation creates meets the policy, not only the primary one: SP 800-108 sibling keys
/// are judged and get the secure defaults, and <c>CKM_HKDF_DATA</c>, which would create a readable
/// data object instead of a key, is refused.
/// </summary>
public sealed class DeriveKeyPolicyTests : IDisposable
{
    private static readonly byte[] BaseKeyBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];

    private readonly Pkcs11Library _library = ManagedToken.NewLibrary();
    private readonly Pkcs11Workspace _workspace;
    private readonly Pkcs11Key _baseKey;

    public DeriveKeyPolicyTests()
    {
        _workspace = ManagedToken.OpenWorkspace(_library);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(BaseKeyBytes).Derive().Build();
        _baseKey = _workspace.ImportKey(template);
    }

    public void Dispose()
    {
        _baseKey.Dispose();
        _workspace.Dispose();
        _library.Dispose();
    }

    private static Mechanism Sp800108With(IReadOnlyList<ObjectAttribute> sibling) =>
        new(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray("label"u8.ToArray()).ByteArray([0x00]).ByteArray("context"u8.ToArray())
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .AddDerivedKey(sibling)
            .Build());

    [Fact]
    public void NonSensitiveSiblingKey_IsRefusedUnderSecureOnly()
    {
        using var sibling = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(16).Sensitive(false).Build();
        using var primary = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => _baseKey.Derive(Sp800108With([.. sibling.Attributes]), primary));

        Assert.IsType<KeyTemplateRequest>(ex.Request);
    }

    [Fact]
    public void SiblingKeyWithNoSensitivityAttributes_GetsTheSecureDefaults()
    {
        using var sibling = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(16).Build();
        using var primary = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();
        var mechanism = Sp800108With([.. sibling.Attributes]);

        using Pkcs11Key derived = _baseKey.Derive(mechanism, primary);
        using Pkcs11Key siblingKey = Assert.Single(((CkmSp800108KdfParams)mechanism.Parameters!).AdditionalDerivedKeys)!;

        using var attrs = siblingKey.GetAttributeValue(CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE);
        Assert.True(attrs[0].GetValueAsBool());
        Assert.False(attrs[1].GetValueAsBool());
    }

    [Fact]
    public void HkdfData_IsRefusedBeforeTheToken_EvenUnderAllowInsecure()
    {
        using var lease = _workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();
        var mechanism = new Mechanism(CKM.CKM_HKDF_DATA, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        var ex = Assert.Throws<ArgumentException>(() => _baseKey.Derive(mechanism, template));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains("CKM_HKDF_DERIVE", ex.Message, StringComparison.Ordinal);
    }
}
