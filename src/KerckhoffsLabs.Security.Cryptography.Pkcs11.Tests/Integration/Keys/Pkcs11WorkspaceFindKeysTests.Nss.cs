using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11WorkspaceFindKeysTests_SoftHsm (OpenKey / ImportKey / FindKeys).</summary>
[Collection("Nss")]
public sealed class Pkcs11WorkspaceFindKeysTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // Finding a freshly *generated* key needs a writable token; NSS's generic token is write-protected.
    public static bool TokenObjects => NssBackendFixture.TokenObjectsAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    [ConditionalFact(nameof(Available))]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [ConditionalFact(nameof(TokenObjects))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var workspace = OpenWorkspace();
        string label = $"octk-find-{Guid.NewGuid():N}";

        using (var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).ValueLen(32).OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. template.Attributes]);
        }

        try
        {
            WorkspaceKeyTestCases.Assert_OpenKey_ByLabel_ReturnsKey(workspace, label);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(filter))
            {
                var h = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
                workspace.Session.DestroyObject(h);
                k.Dispose();
            }
        }
    }

    [ConditionalFact(nameof(Available))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var workspace = OpenWorkspace();

        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < keyMaterial.Length; i++) keyMaterial[i] = (byte)i;
        string label = $"octk-imported-{Guid.NewGuid():N}";

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(keyMaterial).Encrypt().Decrypt().Build();

        using Pkcs11Key key = workspace.ImportKey(template);
        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
        }
        finally { workspace.Session.DestroyObject(key.PrivateHandle); }
    }
}
