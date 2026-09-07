using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateRsaSigningKeyPair</c>. The per-backend
/// test classes live in <c>GenerateRsaKeyPairTests.Pkcs11Mock.cs</c> and <c>GenerateRsaKeyPairTests.SoftHsm2.cs</c>.
/// </summary>
internal static class GenerateRsaKeyPairTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // A non-positive size is always an argument error.
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRsaSigningKeyPair(modulusBits: 0));
        // Sub-2048 (NIST SP 800-131A) is gated behind AllowInsecure, not silently produced.
        Assert.Throws<InsecureOperationException>(() => workspace.GenerateRsaSigningKeyPair(modulusBits: 1024));
    }

    internal static void Assert_GeneratesRsa2048KeyPair(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // 2048 keeps the SoftHSM round-trip fast; the production default is 4096.
        using var key = workspace.GenerateRsaSigningKeyPair(modulusBits: 2048);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }

    /// <summary>
    /// A signing pair must not carry <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — mixing signing and
    /// key-transport roles on one RSA key pair is unsafe. Use <c>GenerateRsaKeyTransportKeyPair</c>
    /// for a dedicated encryption pair.
    /// </summary>
    internal static void Assert_SigningKeyPair_HasNoEncryptCapability(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateRsaSigningKeyPair(modulusBits: 2048);

        using var pubAttrs = workspace.Session.GetAttributeValue(key.PublicHandle, [CKA.CKA_VERIFY, CKA.CKA_ENCRYPT]);
        Assert.True(pubAttrs[0].GetValueAsBool());
        Assert.False(pubAttrs[1].GetValueAsBool());

        using var privAttrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_SIGN, CKA.CKA_DECRYPT]);
        Assert.True(privAttrs[0].GetValueAsBool());
        Assert.False(privAttrs[1].GetValueAsBool());
    }

    /// <summary>
    /// A key-transport pair must not carry <c>CKA_SIGN</c>/<c>CKA_VERIFY</c> and must not carry
    /// <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c> either.
    /// </summary>
    internal static void Assert_GeneratesTransportKeyPair_EncryptDecryptOnly(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateRsaKeyTransportKeyPair(modulusBits: 2048);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);

        using var pubAttrs = workspace.Session.GetAttributeValue(key.PublicHandle, [CKA.CKA_ENCRYPT, CKA.CKA_VERIFY, CKA.CKA_WRAP]);
        Assert.True(pubAttrs[0].GetValueAsBool());
        Assert.False(pubAttrs[1].GetValueAsBool());
        Assert.False(pubAttrs[2].GetValueAsBool());

        using var privAttrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_DECRYPT, CKA.CKA_SIGN, CKA.CKA_UNWRAP]);
        Assert.True(privAttrs[0].GetValueAsBool());
        Assert.False(privAttrs[1].GetValueAsBool());
        Assert.False(privAttrs[2].GetValueAsBool());
    }
}
