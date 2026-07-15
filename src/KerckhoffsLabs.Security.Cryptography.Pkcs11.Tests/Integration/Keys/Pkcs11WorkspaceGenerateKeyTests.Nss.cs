using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11WorkspaceGenerateKeyTests_SoftHsm.</summary>
[Collection("Nss")]
public sealed class Pkcs11WorkspaceGenerateKeyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // NSS's generic token is write-protected, so these token-object cases skip (see NssBackendFixture).
    public static bool TokenObjects => NssBackendFixture.TokenObjectsAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    [ConditionalFact(nameof(TokenObjects))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var workspace = OpenWorkspace();

        string label = $"octk-gen-{Guid.NewGuid():N}";
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
        }
        finally { workspace.Session.DestroyObject(key.PrivateHandle); }
    }

    [ConditionalFact(nameof(TokenObjects))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var workspace = OpenWorkspace();

        string label = $"octk-gen-pair-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_RSA, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.False(key.PublicHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
            workspace.Session.DestroyObject(key.PublicHandle);
        }
    }
}
