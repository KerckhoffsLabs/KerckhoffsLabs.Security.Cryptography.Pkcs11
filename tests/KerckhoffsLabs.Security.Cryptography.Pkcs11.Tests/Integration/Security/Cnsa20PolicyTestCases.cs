using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// Backend-agnostic checks of <see cref="CryptoPolicy.Cnsa20"/> on a real token: CNSA 2.0 keys and mechanisms
/// reach the module and work, and keys of a weaker size or parameter set are refused, whether the caller asks
/// for one, the token has just made one, or one already sits on the token.
/// </summary>
/// <remarks>
/// Keys that must outlive a session are token objects with a unique label, destroyed in <c>finally</c>.
/// A case that needs a "key made under another policy" generates it under the default policy and opens it
/// by label under <see cref="CryptoPolicy.Cnsa20"/>.
/// </remarks>
internal static class Cnsa20PolicyTestCases
{
    private static Pkcs11Session OpenCnsa20(IPkcs11Backend backend) =>
        backend.RequiresUserLogin
            ? backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span), CryptoPolicy.Cnsa20)
            : backend.Library.OpenSessionWithoutLogin(backend.TokenLabel, CryptoPolicy.Cnsa20);

    private static string NewLabel(string kind) => $"cnsa20-{kind}-{Guid.NewGuid():N}";

    private static void RequireTokenObjects(IPkcs11Backend backend)
    {
        if (!backend.SupportsTokenObjects)
            Assert.Skip("Backend has no token objects, so a key can't outlive the session that made it.");
    }

    private static Mechanism Gcm(byte[] iv) => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128));

    private static void AssertKeyStrengthRefusal(CryptoPolicyViolationException ex, KeyStrengthSource source)
    {
        Assert.Equal("Cnsa20", ex.PolicyName);
        var request = Assert.IsType<KeyStrengthRequest>(ex.Request);
        Assert.Equal(source, request.Source);
    }

    private static int CountByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        using var found = session.FindObjects(filter);
        return found.Count;
    }

    // A login is token-wide, so two logged-in sessions can't coexist on most tokens. A key "made under another
    // policy" is therefore generated in a session that is closed before the Cnsa20 one opens, and the leftovers
    // are removed by label from a fresh session once the Cnsa20 one is gone.
    private static void DestroyByLabel(IPkcs11Backend backend, params string[] labels)
    {
        using var session = backend.OpenSession();
        foreach (string label in labels)
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            using var found = session.FindObjects(filter);
            foreach (var obj in found)
                obj.Destroy();
        }
    }

    private static (ObjectTemplate Pub, ObjectTemplate Priv) KeyPairTemplates(
        CKK type, string label, ulong parameterSet, bool persist, bool forKem)
    {
        byte[] id = TestKeys.IdFor(label);
        var pub = ObjectTemplate.ForPublicKey(type).Label(label).Id(id).OnToken(persist)
            .Attribute(CKA.CKA_PARAMETER_SET, parameterSet);
        var priv = ObjectTemplate.ForPrivateKey(type).Label(label).Id(id).OnToken(persist);
        if (forKem)
        {
            pub = pub.Attribute(CKA.CKA_ENCAPSULATE, true);
            priv = priv.Attribute(CKA.CKA_DECAPSULATE, true);
        }
        else
        {
            pub = pub.Verify();
            priv = priv.Sign();
        }
        return (pub.Build(), priv.Build());
    }

    private static Pkcs11Key GenerateMlDsa(Pkcs11Session session, string label, CkpMlDsa set, bool persist)
    {
        var (pub, priv) = KeyPairTemplates(CKK.CKK_ML_DSA, label, (ulong)set, persist, forKem: false);
        using (pub)
        using (priv)
            return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), pub, priv);
    }

    private static Pkcs11Key GenerateMlKem(Pkcs11Session session, string label, CkpMlKem set, bool persist)
    {
        var (pub, priv) = KeyPairTemplates(CKK.CKK_ML_KEM, label, (ulong)set, persist, forKem: true);
        using (pub)
        using (priv)
            return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pub, priv);
    }

    private static ObjectTemplate AesSharedKeyTemplate(bool valueLen)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES).OnToken(false).Sensitive().NonExtractable().Encrypt().Decrypt();
        if (valueLen)
            builder = builder.ValueLen(32);
        return builder.Build();
    }

    internal static void Assert_Aes256Gcm_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM);
        using var session = OpenCnsa20(backend);
        using var key = session.GenerateAesKey(256);
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = [1, 2, 3, 4];

        byte[] ct = key.Encrypt(Gcm(iv), plaintext);
        byte[] pt = key.Decrypt(Gcm(iv), ct);

        Assert.Equal(plaintext, pt);
    }

    internal static void Assert_Aes128_IsRefused_AtGeneration_BeforeTheToken(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        RequireTokenObjects(backend);
        string label = NewLabel("aes128");
        try
        {
            using var session = OpenCnsa20(backend);

            var ex = Assert.Throws<CryptoPolicyViolationException>(() => session.GenerateAesKey(128, label, persistOnToken: true));

            AssertKeyStrengthRefusal(ex, KeyStrengthSource.Template);
            Assert.Equal(0, CountByLabel(session, label));
        }
        finally
        {
            DestroyByLabel(backend, label);
        }
    }

    internal static void Assert_Aes128FromAnotherPolicy_IsRefused_AtUse(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM);
        RequireTokenObjects(backend);
        string label = NewLabel("aes128-existing");
        try
        {
            using (var other = backend.OpenSession())
            using (other.GenerateAesKey(128, label, persistOnToken: true)) { }

            using var session = OpenCnsa20(backend);
            using var key = session.OpenKey(label);

            var ex = Assert.Throws<CryptoPolicyViolationException>(
                () => key.Encrypt(Gcm(RandomNumberGenerator.GetBytes(12)), [1]));

            AssertKeyStrengthRefusal(ex, KeyStrengthSource.ExistingKey);
        }
        finally
        {
            DestroyByLabel(backend, label);
        }
    }

    // A KEK made under the default policy, and the wrapped form of a fresh AES key of targetBytes bytes.
    private static byte[] WrapAesKeyUnderNewKek(IPkcs11Backend backend, string kekLabel, int targetBytes)
    {
        using var other = backend.OpenSession();
        // Plain wrap/unwrap flags rather than GenerateAesKeyEncryptionKey: wolfPKCS11 refuses its CKA_WRAP_TEMPLATE
        // / CKA_UNWRAP_TEMPLATE (CKR_ATTRIBUTE_VALUE_INVALID), and the KEK's own templates aren't under test here.
        using var kek = other.GenerateKey(
            new Mechanism(CKM.CKM_AES_KEY_GEN),
            ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(kekLabel).ValueLen(32).Sensitive().NonExtractable()
                .Wrap().Unwrap().OnToken(true).Build());
        using var target = other.GenerateKey(
            new Mechanism(CKM.CKM_AES_KEY_GEN),
            ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(targetBytes).Sensitive().Extractable().Build());
        return kek.Wrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), target);
    }

    // No CKA_VALUE_LEN: SoftHSM2 treats it as read-only on unwrap, so the size is only known once the token
    // has made the key and the post-check reads it back.
    private static ObjectTemplate UnwrapTemplate(string label) =>
        ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label)
            .Sensitive().NonExtractable().Encrypt().Decrypt().OnToken(true).Build();

    // tokenReportsNoValueLenOnUnwrap pins SoftHSM2, which creates the unwrapped key with no usable CKA_VALUE_LEN
    // (it reads as 0, which the session treats as unreported). The policy fails closed, so the unwrap is refused
    // with "did not report" and the case asserts that instead; the pin can go once SoftHSM2 reports the length.
    internal static void Assert_AesKw_UnwrapsAes256(IPkcs11Backend backend, bool tokenReportsNoValueLenOnUnwrap = false)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_KEY_WRAP);
        RequireTokenObjects(backend);
        string kekLabel = NewLabel("kek");
        string unwrapLabel = NewLabel("unwrapped256");
        try
        {
            byte[] wrapped = WrapAesKeyUnderNewKek(backend, kekLabel, 32);

            using var session = OpenCnsa20(backend);
            using var kek = session.OpenKey(kekLabel);
            using var template = UnwrapTemplate(unwrapLabel);
            if (tokenReportsNoValueLenOnUnwrap)
            {
                var refusal = Assert.Throws<CryptoPolicyViolationException>(
                    () => kek.Unwrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, template));
                AssertKeyStrengthRefusal(refusal, KeyStrengthSource.CreatedKey);
                Assert.Null(Assert.IsType<KeyStrengthRequest>(refusal.Request).ValueLengthBytes);
                Assert.Contains("did not report", refusal.Reason, StringComparison.Ordinal);
                Assert.Contains("so CNSA 2.0 compliance can't be verified", refusal.Reason, StringComparison.Ordinal);
                Assert.Equal(0, CountByLabel(session, unwrapLabel));
                return;
            }

            using var unwrapped = kek.Unwrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, template);

            byte[] iv = RandomNumberGenerator.GetBytes(12);
            byte[] ct = unwrapped.Encrypt(Gcm(iv), [9, 9]);
            Assert.Equal(new byte[] { 9, 9 }, unwrapped.Decrypt(Gcm(iv), ct));
        }
        finally
        {
            DestroyByLabel(backend, kekLabel, unwrapLabel);
        }
    }

    internal static void Assert_AesKw_UnwrapOfAes128_IsRefused_AndLeavesNoKey(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_KEY_WRAP);
        RequireTokenObjects(backend);
        string kekLabel = NewLabel("kek");
        string unwrapLabel = NewLabel("unwrapped128");
        try
        {
            byte[] wrapped = WrapAesKeyUnderNewKek(backend, kekLabel, 16);

            using var session = OpenCnsa20(backend);
            using var kek = session.OpenKey(kekLabel);
            using var template = UnwrapTemplate(unwrapLabel);

            var ex = Assert.Throws<CryptoPolicyViolationException>(
                () => kek.Unwrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, template));

            AssertKeyStrengthRefusal(ex, KeyStrengthSource.CreatedKey);
            Assert.Equal(0, CountByLabel(session, unwrapLabel));
        }
        finally
        {
            DestroyByLabel(backend, kekLabel, unwrapLabel);
        }
    }

    internal static void Assert_MlKem1024_EncapsulatesAndDecapsulates(IPkcs11Backend backend)
    {
        backend.RequireMlKemParameterSet(MLKemAlgorithm.MLKem1024.EncapsulationKeySizeInBytes);
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        using var session = OpenCnsa20(backend);
        using var key = GenerateMlKem(session, NewLabel("mlkem1024"), CkpMlKem.CKP_ML_KEM_1024, persist: false);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ML_KEM);
            using var encTemplate = AesSharedKeyTemplate(valueLen: true);
            var (ciphertext, encKey) = key.EncapsulateKey(mechanism, encTemplate, MLKemAlgorithm.MLKem1024.CiphertextSizeInBytes);
            using (encKey)
            {
                try
                {
                    using var decTemplate = AesSharedKeyTemplate(valueLen: true);
                    using var decKey = key.DecapsulateKey(mechanism, ciphertext, decTemplate);
                    try
                    {
                        byte[] iv = RandomNumberGenerator.GetBytes(12);
                        byte[] plaintext = [4, 5, 6];
                        Assert.Equal(plaintext, decKey.Decrypt(Gcm(iv), encKey.Encrypt(Gcm(iv), plaintext)));
                    }
                    finally
                    {
                        decKey.Destroy();
                    }
                }
                finally
                {
                    encKey.Destroy();
                }
            }
        }
        finally
        {
            key.Destroy();
        }
    }

    internal static void Assert_MlKem768_IsRefused_AtGeneration(IPkcs11Backend backend)
    {
        backend.RequireMlKemParameterSet(MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes);
        RequireTokenObjects(backend);
        string label = NewLabel("mlkem768");
        try
        {
            using var session = OpenCnsa20(backend);

            var ex = Assert.Throws<CryptoPolicyViolationException>(
                () => GenerateMlKem(session, label, CkpMlKem.CKP_ML_KEM_768, persist: true));

            AssertKeyStrengthRefusal(ex, KeyStrengthSource.Template);
            Assert.Equal(0, CountByLabel(session, label));
        }
        finally
        {
            DestroyByLabel(backend, label);
        }
    }

    internal static void Assert_MlDsa87_SignsAndVerifies(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        using var session = OpenCnsa20(backend);
        using var key = GenerateMlDsa(session, NewLabel("mldsa87"), CkpMlDsa.CKP_ML_DSA_87, persist: false);
        try
        {
            byte[] data = [1, 2, 3];
            byte[] signature = key.Sign(Pkcs11MechanismMap.MlDsaSign(), data);

            Assert.True(key.Verify(Pkcs11MechanismMap.MlDsaSign(), data, signature));
        }
        finally
        {
            key.Destroy();
        }
    }

    internal static void Assert_MlDsa65FromAnotherPolicy_IsRefused_AtUse(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        RequireTokenObjects(backend);
        string label = NewLabel("mldsa65-existing");
        try
        {
            using (var other = backend.OpenSession())
            using (GenerateMlDsa(other, label, CkpMlDsa.CKP_ML_DSA_65, persist: true)) { }

            using var session = OpenCnsa20(backend);
            using var key = session.OpenKey(label);

            var ex = Assert.Throws<CryptoPolicyViolationException>(
                () => key.Sign(Pkcs11MechanismMap.MlDsaSign(), [1, 2, 3]));

            AssertKeyStrengthRefusal(ex, KeyStrengthSource.ExistingKey);
        }
        finally
        {
            DestroyByLabel(backend, label);
        }
    }

    internal static void Assert_RsaPss_IsRefused_BeforeTheToken(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        RequireTokenObjects(backend);
        string label = NewLabel("rsa");
        try
        {
            using (var other = backend.OpenSession())
            using (other.GenerateRsaSigningKeyPair(3072, label, persistOnToken: true)) { }

            using var session = OpenCnsa20(backend);
            using var key = session.OpenKey(label);
            var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

            var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.Sign(pss, [1, 2, 3]));

            Assert.Equal("Cnsa20", ex.PolicyName);
            Assert.Equal(CKM.CKM_SHA256_RSA_PKCS_PSS, ex.Mechanism);
        }
        finally
        {
            DestroyByLabel(backend, label);
        }
    }
}
