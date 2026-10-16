using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic key lookup assertions (<c>OpenKey</c> / <c>FindKeys</c> / <c>ImportKey</c>). The
/// per-backend test classes live in <c>Pkcs11SessionFindKeysTests.Pkcs11Mock.cs</c>,
/// <c>.SoftHsm2.cs</c>, <c>.Nss.cs</c>, <c>.OpenCryptoki.cs</c>, and <c>.Kryoptic.cs</c>.
/// </summary>
internal static class SessionKeyTestCases
{
    public static void Assert_OpenKey_ByLabel_ReturnsKey(Pkcs11Session session, string label)
    {
        using var key = session.OpenKey(label);
        Assert.NotNull(key);
        Assert.Equal(label, key.Label);
    }

    public static void Assert_OpenKey_NotFound_Throws(Pkcs11Session session) => Assert.Throws<Pkcs11ObjectNotFoundException>(() => session.OpenKey("does-not-exist-zzzz"));

    public static void Assert_FindKeys_NoMatch_ReturnsEmpty(Pkcs11Session session)
    {
        using var filter = ObjectTemplate.Empty()
            .Label("definitely-no-such-label-9999")
            .Build();
        var keys = session.FindKeys(filter);
        Assert.Empty(keys);
    }

    /// <summary>Generates a token-object AES key directly on the session, then confirms
    /// <c>OpenKey</c> finds it by label — a real round-trip through the token's own object store,
    /// not just the mock's in-memory template.</summary>
    public static void Assert_OpenKey_AfterGenerate_FindsKey(Pkcs11Session session)
    {
        string label = $"test-key-{Guid.NewGuid():N}";

        using (var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).ValueLen(32).OnToken().Build())
        {
            session.Core.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. template.Attributes]);
        }

        try
        {
            Assert_OpenKey_ByLabel_ReturnsKey(session, label);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            using var keys = session.FindKeys(filter);
            foreach (var k in keys)
            {
                var h = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
                session.Core.DestroyObject(h);
            }
        }
    }

    public static void Assert_ImportKey_AesValue_RoundTrips(Pkcs11Session session)
    {
        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < keyMaterial.Length; i++) keyMaterial[i] = (byte)i;
        string label = $"imported-{Guid.NewGuid():N}";

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(keyMaterial).Encrypt().Decrypt().Build();

        using Pkcs11Key key = session.ImportKey(template);
        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
        }
        finally { session.Core.DestroyObject(key.PrivateHandle); }
    }
}
