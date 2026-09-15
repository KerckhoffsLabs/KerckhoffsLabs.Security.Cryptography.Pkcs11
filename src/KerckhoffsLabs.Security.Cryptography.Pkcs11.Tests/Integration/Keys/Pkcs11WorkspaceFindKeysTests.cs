using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic key lookup assertions (<c>OpenKey</c> / <c>FindKeys</c> / <c>ImportKey</c>). The
/// per-backend test classes live in <c>Pkcs11WorkspaceFindKeysTests.Pkcs11Mock.cs</c>,
/// <c>.SoftHsm2.cs</c>, <c>.Nss.cs</c>, <c>.OpenCryptoki.cs</c>, and <c>.Kryoptic.cs</c>.
/// </summary>
internal static class WorkspaceKeyTestCases
{
    public static void Assert_OpenKey_ByLabel_ReturnsKey(Pkcs11Workspace workspace, string label)
    {
        using var key = workspace.OpenKey(label);
        Assert.NotNull(key);
        Assert.Equal(label, key.Label);
    }

    public static void Assert_OpenKey_NotFound_Throws(Pkcs11Workspace workspace) => Assert.Throws<Pkcs11ObjectException>(() => workspace.OpenKey("does-not-exist-zzzz"));

    public static void Assert_FindKeys_NoMatch_ReturnsEmpty(Pkcs11Workspace workspace)
    {
        using var filter = ObjectTemplate.Empty()
            .Label("definitely-no-such-label-9999")
            .Build();
        var keys = workspace.FindKeys(filter);
        Assert.Empty(keys);
    }

    /// <summary>Generates a token-object AES key directly on the session, then confirms
    /// <c>OpenKey</c> finds it by label — a real round-trip through the token's own object store,
    /// not just the mock's in-memory template.</summary>
    public static void Assert_OpenKey_AfterGenerate_FindsKey(Pkcs11Workspace workspace)
    {
        string label = $"test-key-{Guid.NewGuid():N}";

        using (var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).ValueLen(32).OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. template.Attributes]);
        }

        try
        {
            Assert_OpenKey_ByLabel_ReturnsKey(workspace, label);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            using var keys = workspace.FindKeys(filter);
            foreach (var k in keys)
            {
                var h = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
                workspace.Session.DestroyObject(h);
            }
        }
    }

    public static void Assert_ImportKey_AesValue_RoundTrips(Pkcs11Workspace workspace)
    {
        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < keyMaterial.Length; i++) keyMaterial[i] = (byte)i;
        string label = $"imported-{Guid.NewGuid():N}";

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
