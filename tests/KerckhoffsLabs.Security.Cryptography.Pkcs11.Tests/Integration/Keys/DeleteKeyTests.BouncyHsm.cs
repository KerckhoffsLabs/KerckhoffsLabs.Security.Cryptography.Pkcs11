using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BouncyHsm counterpart of DeleteKeyTests_SoftHsm: Pkcs11Key.Delete removes the object.</summary>
[Collection("BouncyHsm")]
public sealed class DeleteKeyTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Delete_RemovesKeyFromToken()
    {
        using var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"octk-del-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        using (session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl)) { }

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var before = session.FindKeys(filter);
            Assert.NotEmpty(before);
            foreach (var k in before) k.Dispose();
        }

        using (var key = session.OpenKey(label))
            key.Destroy();

        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(session.FindKeys(filter));
    }
}
