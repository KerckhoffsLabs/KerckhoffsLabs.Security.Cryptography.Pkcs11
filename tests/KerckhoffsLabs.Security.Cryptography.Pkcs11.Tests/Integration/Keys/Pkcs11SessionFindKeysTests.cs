using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
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

    /// <summary>A certificate is stored under its key's <c>CKA_ID</c>; looking keys up by that id must return the
    /// two halves of the pair and nothing else, not fail turning the certificate into a key.</summary>
    public static void Assert_FindKeys_ById_LeavesOutACertificateWithThatId(Pkcs11Session session)
    {
        string label = $"findkeys-cert-{Guid.NewGuid():N}";
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using Pkcs11Key pair = GenerateEcSigningPair(session, label, id);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FindKeys leaves certificates out", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using Pkcs11Certificate stored = session.ImportCertificate(certificate, label, id);

        using var filter = ObjectTemplate.Empty().Id(id).Build();
        using var keys = session.FindKeys(filter);

        Assert.Equal(2, keys.Count);
        Assert.All(keys, key => Assert.Equal(CKK.CKK_EC, key.KeyType));
    }

    public static void Assert_FindKeys_RefusesANonKeyClass(Pkcs11Session session)
    {
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_CERTIFICATE).Build();
        Assert.Throws<ArgumentException>(() => session.FindKeys(filter));
    }

    /// <summary>A key pair is two objects with attributes of their own: naming the half reads that half, so the
    /// private key's protection and role can be checked; the unnamed overload still reads the public key.</summary>
    public static void Assert_GetAttributeValue_ReadsTheNamedHalf(Pkcs11Session session)
    {
        // Generated from templates that share a CKA_ID, then opened by label: the two halves are found as one key.
        string label = $"attr-half-{Guid.NewGuid():N}";
        using (GenerateEcSigningPair(session, label, RandomNumberGenerator.GetBytes(16))) { }
        using Pkcs11Key pair = session.OpenKey(label);

        using (var attrs = pair.GetAttributeValue(KeyHandlePart.Private, CKA.CKA_CLASS, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_SIGN))
        {
            Assert.Equal(CKO.CKO_PRIVATE_KEY, (CKO)attrs[0].GetValueAsUlong());
            Assert.True(attrs[1].GetValueAsBool());
            Assert.False(attrs[2].GetValueAsBool());
            Assert.True(attrs[3].GetValueAsBool());
        }

        using (var attrs = pair.GetAttributeValue(KeyHandlePart.Public, CKA.CKA_CLASS, CKA.CKA_VERIFY))
        {
            Assert.Equal(CKO.CKO_PUBLIC_KEY, (CKO)attrs[0].GetValueAsUlong());
            Assert.True(attrs[1].GetValueAsBool());
        }

        using (var attrs = pair.GetAttributeValue(CKA.CKA_CLASS))
            Assert.Equal(CKO.CKO_PUBLIC_KEY, (CKO)attrs[0].GetValueAsUlong());
    }

    public static void Assert_GetAttributeValue_PublicPartOfASecretKey_Throws(Pkcs11Session session)
    {
        using Pkcs11Key secret = session.GenerateAesKey(bitLength: 256);

        using (var attrs = secret.GetAttributeValue(KeyHandlePart.Private, CKA.CKA_CLASS))
            Assert.Equal(CKO.CKO_SECRET_KEY, (CKO)attrs[0].GetValueAsUlong());

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => secret.GetAttributeValue(KeyHandlePart.Public, CKA.CKA_CLASS));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    // A P-256 signing pair whose halves share label and CKA_ID; sensitive, non-extractable session objects.
    private static Pkcs11Key GenerateEcSigningPair(Pkcs11Session session, string label, byte[] id)
    {
        using var publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Build();
        using var privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Sensitive().NonExtractable().Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate);
    }
}
