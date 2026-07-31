using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// SoftHSM-only: <see cref="Pkcs11Key.Destroy"/> removes the token object via C_DestroyObject.
/// Requires a real token to verify the object is actually gone after deletion.
/// </summary>
[Collection("SoftHsm")]
public sealed class DeleteKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Delete_RemovesKeyFromToken()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"del-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        using (workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl)) { }

        // Present on the token before deletion.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var before = workspace.FindKeys(filter);
            Assert.NotEmpty(before);
            foreach (var k in before) k.Dispose();
        }

        using (var key = workspace.OpenKey(label))
            key.Destroy();

        // Gone after deletion.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(workspace.FindKeys(filter));
    }
}
