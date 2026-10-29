using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
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

    // A copy keeps CKA_LOCAL: TRUE "only if key was either generated locally ... or created with a C_CopyObject call
    // as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE" (§4.8, Table 26). The copy of a
    // generated AES key reads TRUE, the copy of an imported one FALSE.
    internal static void Assert_CopyOfAKey_KeepsCkaLocal(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(backend);
        var made = new List<ObjectHandle>();
        try
        {
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
            using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"local-copy-{Guid.NewGuid():N}");
            ObjectHandle generated = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [attrClass, attrKeyType, attrToken, attrValueLen, attrEncrypt]);
            made.Add(generated);
            ObjectHandle imported = session.CreateObject([attrClass, attrKeyType, attrToken, attrValue, attrEncrypt]);
            made.Add(imported);
            ObjectHandle generatedCopy = session.CopyObject(generated, [attrLabel]);
            made.Add(generatedCopy);
            ObjectHandle importedCopy = session.CopyObject(imported, [attrLabel]);
            made.Add(importedCopy);

            Assert.True(ReadBool(session, generated, CKA.CKA_LOCAL), "A generated key reports CKA_LOCAL false.");
            Assert.True(ReadBool(session, generatedCopy, CKA.CKA_LOCAL), "The copy of a generated key reports CKA_LOCAL false.");
            Assert.False(ReadBool(session, importedCopy, CKA.CKA_LOCAL), "The copy of an imported key reports CKA_LOCAL true.");
        }
        finally
        {
            foreach (ObjectHandle handle in made)
                session.DestroyObject(handle);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // CKM_PKCS5_PBKD2 is a key generation mechanism (C_GenerateKey), so the key it makes is CKA_LOCAL with
    // CKA_KEY_GEN_MECHANISM = CKM_PKCS5_PBKD2 (§4.8: CKA_LOCAL is TRUE for a key generated with C_GenerateKey, and
    // CKA_KEY_GEN_MECHANISM names the mechanism that generated it); made sensitive and unextractable, it is also
    // CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE (§4.11). CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_SENSITIVE and
    // CKA_NEVER_EXTRACTABLE are checked where the token reports them; ObjectConformanceTestCases'
    // provenance case pins which ones each backend does.
    internal static void Assert_Pbkdf2Key_RecordsItsGeneration(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_PKCS5_PBKD2,
                new CkmPkcs5Pbkd2Params(Encoding.UTF8.GetBytes("kl-provenance-salt"), 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, Encoding.UTF8.GetBytes("kl-provenance-password")));
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
            ObjectHandle key = session.GenerateKey(mechanism, [attrClass, attrKeyType, attrToken, attrValueLen, attrSensitive, attrExtractable]);
            try
            {
                using var read = session.GetAttributeValue(key, [CKA.CKA_LOCAL, CKA.CKA_KEY_GEN_MECHANISM, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE]);
                Assert.True(read[0].GetValueAsBool(), "A key generated with CKM_PKCS5_PBKD2 reports CKA_LOCAL false.");
                if (!read[1].CannotBeRead)
                    Assert.Equal((ulong)CKM.CKM_PKCS5_PBKD2, read[1].GetValueAsUlong());
                if (!read[2].CannotBeRead)
                    Assert.True(read[2].GetValueAsBool(), "A key generated sensitive with CKM_PKCS5_PBKD2 is not CKA_ALWAYS_SENSITIVE.");
                if (!read[3].CannotBeRead)
                    Assert.True(read[3].GetValueAsBool(), "A key generated unextractable with CKM_PKCS5_PBKD2 is not CKA_NEVER_EXTRACTABLE.");
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    public static TheoryData<string> DerivationMechanisms => ["HKDF", "ECDH"];

    // A derived key's history follows its base key (the key sensitivity rules of CKM_HKDF_DERIVE, §6.62.3, and
    // CKM_ECDH1_DERIVE, §6.3.17): CKA_ALWAYS_SENSITIVE is FALSE if the base's is, and otherwise the derived key's
    // CKA_SENSITIVE; CKA_NEVER_EXTRACTABLE is FALSE if the base's is, and otherwise the opposite of the derived
    // key's CKA_EXTRACTABLE. Checked from a generated base and from an imported one, both sensitive and
    // unextractable, with a template asking the same: the rule is applied to what the token reports for each
    // base, so it holds whatever the token records for an imported key. ECDH runs with CKD_NULL, which the
    // library's default policy refuses into a key with any use: the case is about the attributes, not the KDF.
    // Skips a token that does not report both attributes.
    internal static void Assert_DerivedKey_TakesItsHistoryFromTheBase(IPkcs11Backend backend, string derivation)
    {
        if (derivation == "HKDF")
            backend.RequireMechanisms(CKM.CKM_HKDF_DERIVE, CKM.CKM_GENERIC_SECRET_KEY_GEN);
        else
            backend.RequireMechanisms(CKM.CKM_ECDH1_DERIVE, CKM.CKM_EC_KEY_PAIR_GEN);
        using Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(backend);
        var made = new List<ObjectHandle>();
        try
        {
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrEc = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
            using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
            using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);

            ObjectHandle generatedBase, importedBase;
            Mechanism mechanism;
            if (derivation == "HKDF")
            {
                generatedBase = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), [attrSecret, attrGeneric, attrToken, attrLen32, attrSensitive, attrExtractable, attrDerive]);
                made.Add(generatedBase);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
                importedBase = session.CreateObject([attrSecret, attrGeneric, attrToken, attrSensitive, attrExtractable, attrDerive, attrValue]);
                made.Add(importedBase);
                mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
            }
            else
            {
                session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [attrToken, attrEcParams],
                    [attrToken, attrSensitive, attrExtractable, attrDerive], out ObjectHandle generatedPublic, out generatedBase);
                made.Add(generatedPublic);
                made.Add(generatedBase);
                using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                ECParameters imported = ecdh.ExportParameters(includePrivateParameters: true);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, imported.D!);
                importedBase = session.CreateObject([attrPrivate, attrEc, attrToken, attrEcParams, attrSensitive, attrExtractable, attrDerive, attrValue]);
                made.Add(importedBase);
                using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                ECParameters peerKey = peer.ExportParameters(includePrivateParameters: false);
                mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, TestKeys.DerEcPoint(peerKey.Q.X!, peerKey.Q.Y!)));
            }

            foreach ((string which, ObjectHandle baseKey) in new[] { ("generated", generatedBase), ("imported", importedBase) })
            {
                using var baseRead = session.GetAttributeValue(baseKey, [CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE]);
                if (baseRead[0].CannotBeRead || baseRead[1].CannotBeRead)
                    Assert.Skip("The backend does not report CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE.");
                bool baseAlwaysSensitive = baseRead[0].GetValueAsBool();
                bool baseNeverExtractable = baseRead[1].GetValueAsBool();

                ObjectHandle derived;
                using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                    derived = session.DeriveKey(mechanism, baseKey, [attrSecret, attrGeneric, attrToken, attrLen32, attrSensitive, attrExtractable, attrDerive]);
                made.Add(derived);
                using var read = session.GetAttributeValue(derived, [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE]);
                bool expectedAlwaysSensitive = baseAlwaysSensitive && read[0].GetValueAsBool();
                bool expectedNeverExtractable = baseNeverExtractable && !read[1].GetValueAsBool();
                Assert.True(read[2].GetValueAsBool() == expectedAlwaysSensitive,
                    $"{derivation} from the {which} base (CKA_ALWAYS_SENSITIVE {baseAlwaysSensitive}): the derived key's CKA_ALWAYS_SENSITIVE is {read[2].GetValueAsBool()}.");
                Assert.True(read[3].GetValueAsBool() == expectedNeverExtractable,
                    $"{derivation} from the {which} base (CKA_NEVER_EXTRACTABLE {baseNeverExtractable}): the derived key's CKA_NEVER_EXTRACTABLE is {read[3].GetValueAsBool()}.");
            }
        }
        finally
        {
            foreach (ObjectHandle handle in made)
                session.DestroyObject(handle);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    private static bool ReadBool(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsBool();
    }
}
