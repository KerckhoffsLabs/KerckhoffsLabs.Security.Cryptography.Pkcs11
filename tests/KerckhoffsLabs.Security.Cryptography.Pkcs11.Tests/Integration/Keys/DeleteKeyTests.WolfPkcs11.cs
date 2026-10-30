using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Real-token only: <see cref="Pkcs11Key.Destroy"/> removes the token object via C_DestroyObject.
/// Requires a real token to verify the object is actually gone after deletion.
/// </summary>
[Collection("WolfPkcs11")]
public sealed class DeleteKeyTests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Delete_RemovesKeyFromToken()
    {
        using var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"del-{Guid.NewGuid():N}";
        using (var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        using (session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl)) { }

        // Present on the token before deletion.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
        {
            var before = session.FindKeys(filter);
            Assert.NotEmpty(before);
            foreach (var k in before) k.Dispose();
        }

        using (var key = session.OpenKey(label))
            key.Destroy();

        // Gone after deletion.
        using (var filter = ObjectTemplate.Empty().Label(label).Build())
            Assert.Empty(session.FindKeys(filter));
    }
}
