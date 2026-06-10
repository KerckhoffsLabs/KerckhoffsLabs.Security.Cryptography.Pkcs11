using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>opencryptoki counterpart of DeleteKeyTests_SoftHsm: Pkcs11Key.Delete removes the object.</summary>
[Collection("OpenCryptoki")]
public sealed class DeleteKeyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void Delete_RemovesKeyFromToken()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"octk-del-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        using (workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl)) { }

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var before = workspace.FindKeys(filter);
            Assert.NotEmpty(before);
            foreach (var k in before) k.Dispose();
        }

        using (var key = workspace.OpenKey(label))
            key.Delete();

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(workspace.FindKeys(filter));
    }
}
