using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// <c>CKA_LOCAL</c>, the token's record of where a key came from. PKCS#11 v3.2 §4.4 sets it to
/// <see langword="true"/> only for a key generated on the token (<c>C_GenerateKey</c>,
/// <c>C_GenerateKeyPair</c>) and to <see langword="false"/> for one imported with <c>C_CreateObject</c>:
/// a caller can rely on it to tell a key that never left the token from one that was brought in.
/// </summary>
internal static class KeyProvenanceTestCases
{
    internal static void Assert_GeneratedSecretKey_IsLocal(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);

        using var session = backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"local-gen-{Guid.NewGuid():N}").ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        try
        {
            Assert.True(IsLocal(key), "A key generated with C_GenerateKey reports CKA_LOCAL false.");
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    // Both halves of the pair: PKCS#11 sets CKA_LOCAL on the public key as well as the private one.
    internal static void Assert_GeneratedKeyPair_IsLocal(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        using var session = backend.OpenSession();
        string label = $"local-pair-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Label(label).Id(id).Verify().EcParams(TestKeys.EcParams("P-256")).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            Assert.True(IsLocal(session, key.PrivateHandle), "A private key generated with C_GenerateKeyPair reports CKA_LOCAL false.");
            Assert.True(IsLocal(session, key.PublicHandle), "A public key generated with C_GenerateKeyPair reports CKA_LOCAL false.");
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    internal static void Assert_ImportedSecretKey_IsNotLocal(IPkcs11Backend backend)
    {
        using var session = backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"local-imp-{Guid.NewGuid():N}").Value(new byte[32]).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        using var key = session.ImportKey(template);
        try
        {
            Assert.False(IsLocal(key), "A key imported with C_CreateObject reports CKA_LOCAL true.");
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    private static bool IsLocal(Pkcs11Key key)
    {
        using var attributes = key.GetAttributeValue(CKA.CKA_LOCAL);
        return attributes[0].GetValueAsBool();
    }

    // One half of a key pair: GetAttributeValue reads the public half when there is one.
    private static bool IsLocal(Pkcs11Session session, ObjectHandle handle)
    {
        using var attributes = session.Core.GetAttributeValue(handle, [CKA.CKA_LOCAL]);
        return attributes[0].GetValueAsBool();
    }
}
