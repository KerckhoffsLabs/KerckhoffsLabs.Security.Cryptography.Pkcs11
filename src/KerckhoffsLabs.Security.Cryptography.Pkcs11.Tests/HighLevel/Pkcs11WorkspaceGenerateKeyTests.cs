using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("SoftHsm")]
public sealed class Pkcs11WorkspaceGenerateKeyTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11WorkspaceGenerateKeyTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var workspace = OpenWorkspace();

        string label = $"gen-{Guid.NewGuid():N}";
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
        }
    }
}
