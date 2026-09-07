using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateAesKey</c>. The per-backend test
/// classes live in <c>GenerateAesKeyTests.Pkcs11Mock.cs</c> and <c>GenerateAesKeyTests.SoftHsm2.cs</c>.
/// </summary>
internal static class GenerateAesKeyTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_RejectsWrongBitLength(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 64));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 100));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 512));
    }

    internal static void Assert_GeneratesAes256Key(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateAesKey(bitLength: 256);

        Assert.False(key.PrivateHandle.IsInvalid);

        using var attrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_VALUE_LEN]);
        Assert.Single(attrs);
        Assert.Equal(32UL, attrs[0].GetValueAsUlong());
    }

    /// <summary>
    /// A key from <c>GenerateAesKey</c> must not be usable to wrap or unwrap other keys — combining
    /// data-decryption and key-wrapping roles on one key is a wrap-oracle vector. Use
    /// <c>GenerateAesKeyEncryptionKey</c> for a dedicated KEK instead.
    /// </summary>
    internal static void Assert_GeneratedKey_HasNoWrapCapability(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateAesKey(bitLength: 256);

        using var attrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT, CKA.CKA_WRAP, CKA.CKA_UNWRAP]);
        Assert.True(attrs[0].GetValueAsBool());
        Assert.True(attrs[1].GetValueAsBool());
        Assert.False(attrs[2].GetValueAsBool());
        Assert.False(attrs[3].GetValueAsBool());
    }

    /// <summary>
    /// <c>GenerateAesKeyEncryptionKey</c> must be usable only to wrap/unwrap — it must not carry
    /// <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c>, or it becomes the same wrap-oracle risk.
    /// </summary>
    internal static void Assert_GeneratesKeyEncryptionKey_WrapUnwrapOnly(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey(bitLength: 256);

        Assert.False(kek.PrivateHandle.IsInvalid);

        using var attrs = workspace.Session.GetAttributeValue(kek.PrivateHandle, [CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT, CKA.CKA_WRAP, CKA.CKA_UNWRAP]);
        Assert.False(attrs[0].GetValueAsBool());
        Assert.False(attrs[1].GetValueAsBool());
        Assert.True(attrs[2].GetValueAsBool());
        Assert.True(attrs[3].GetValueAsBool());
    }
}
