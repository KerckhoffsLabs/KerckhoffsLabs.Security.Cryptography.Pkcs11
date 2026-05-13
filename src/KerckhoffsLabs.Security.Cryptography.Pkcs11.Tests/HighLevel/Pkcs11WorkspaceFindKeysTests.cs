using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

internal static class WorkspaceKeyTestCases
{
    public static void Assert_OpenKey_ByLabel_ReturnsKey(Pkcs11Workspace workspace, string label)
    {
        using var key = workspace.OpenKey(label);
        Assert.NotNull(key);
        Assert.Equal(label, key.Label);
    }

    public static void Assert_OpenKey_NotFound_Throws(Pkcs11Workspace workspace)
    {
        Assert.Throws<Pkcs11ObjectException>(() => workspace.OpenKey("does-not-exist-zzzz"));
    }

    public static void Assert_FindKeys_NoMatch_ReturnsEmpty(Pkcs11Workspace workspace)
    {
        using var filter = ObjectTemplate.Empty()
            .Label("definitely-no-such-label-9999")
            .Build();
        var keys = workspace.FindKeys(filter);
        Assert.Empty(keys);
    }
}

[Collection("Mock")]
public sealed class Pkcs11WorkspaceFindKeysTests_Mock
{
    private readonly MockBackendFixture _backend;
    public Pkcs11WorkspaceFindKeysTests_Mock(MockBackendFixture backend) => _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [Fact]
    public void FindKeys_NoMatch_ReturnsEmpty()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_FindKeys_NoMatch_ReturnsEmpty(workspace);
    }
}

[Collection("SoftHsm")]
public sealed class Pkcs11WorkspaceFindKeysTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11WorkspaceFindKeysTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var workspace = OpenWorkspace();
        string label = $"test-key-{Guid.NewGuid():N}";

        using (var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).ValueLen(32).OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template.Attributes.ToList());
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var workspace = OpenWorkspace();

        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < keyMaterial.Length; i++) keyMaterial[i] = (byte)i;
        string label = $"imported-{Guid.NewGuid():N}";

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label)
            .Value(keyMaterial)
            .Encrypt()
            .Decrypt()
            .Build();

        using Pkcs11Key key = workspace.ImportKey(template);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
        }
    }
}
