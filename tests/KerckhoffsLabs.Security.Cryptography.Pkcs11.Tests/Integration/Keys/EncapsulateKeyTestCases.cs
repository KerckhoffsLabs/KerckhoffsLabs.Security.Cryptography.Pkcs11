using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic round-trip tests for the generic PKCS#11 v3.2 <c>C_EncapsulateKey</c>/
/// <c>C_DecapsulateKey</c> functions with classical (RSA-OAEP, ECDH1) mechanisms, driven directly
/// through <c>Pkcs11Key.EncapsulateKey</c>/<c>DecapsulateKey</c> -- these are mechanism-agnostic
/// already (unlike <c>MLKemPkcs11</c>, which is ML-KEM-specific), so no new façade is needed. Only
/// opencryptoki's soft token advertises <c>CKF_ENCAPSULATE</c>/<c>CKF_DECAPSULATE</c>
/// for these mechanisms (confirmed in <c>soft_specific.c</c>'s mechanism table); Kryoptic, NSS, and
/// SoftHSM2 implement key encapsulation for ML-KEM only, so their test files skip the classical cases.
/// The ML-KEM case runs on every backend: <c>MLKemPkcs11</c> drives the same functions but always into an
/// extractable secret it reads back, so this is the only test of the on-token path, where the shared
/// secret never leaves the token.
/// </summary>
internal static class EncapsulateKeyTestCases
{
    private static Pkcs11Session OpenSession(IPkcs11Backend backend) => backend.OpenSession();

    // A token that lists the mechanism for encryption or derivation only says so through the absent
    // CKF_ENCAPSULATE/CKF_DECAPSULATE flags, and answers C_EncapsulateKey with CKR_MECHANISM_INVALID.
    private static void RequireEncapsulation(IPkcs11Backend backend, CKM mechanism) =>
        backend.RequireMechanismFlags(
            mechanism,
            f => (f.Flags & (CKF.CKF_ENCAPSULATE | CKF.CKF_DECAPSULATE)) == (CKF.CKF_ENCAPSULATE | CKF.CKF_DECAPSULATE),
            "CKF_ENCAPSULATE and CKF_DECAPSULATE");

    private static ObjectTemplate SharedSecretTemplate(bool onToken, bool valueLen = true)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET);
        if (valueLen)
        {
            builder = builder.ValueLen(32);
        }
        return builder.Extractable().Sensitive(false).OnToken(onToken).Build();
    }

    private static void AssertRoundTrips(
        Pkcs11Key key, Mechanism mechanism, bool onToken, bool valueLenOnDecapsulate = true)
    {
        using var encTemplate = SharedSecretTemplate(onToken);
        var (ciphertext, encSecret) = key.EncapsulateKey(mechanism, encTemplate);
        try
        {
            using var decTemplate = SharedSecretTemplate(onToken, valueLenOnDecapsulate);
            using Pkcs11Key decSecret = key.DecapsulateKey(mechanism, ciphertext, decTemplate);

            using var encAttrs = encSecret.GetAttributeValue(CKA.CKA_VALUE);
            using var decAttrs = decSecret.GetAttributeValue(CKA.CKA_VALUE);
            Assert.False(encAttrs[0].CannotBeRead);
            Assert.False(decAttrs[0].CannotBeRead);
            Assert.Equal(encAttrs[0].GetValueAsByteArray(), decAttrs[0].GetValueAsByteArray());
        }
        finally
        {
            using (encSecret) { encSecret.Destroy(); }
        }
    }

    internal static void Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(IPkcs11Backend backend)
    {
        RequireEncapsulation(backend, CKM.CKM_RSA_PKCS_OAEP);
        using var session = OpenSession(backend);
        // Reading the shared secret back to compare is the extract-and-destroy path, gated by the
        // secure-defaults policy.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);

        string label = $"encap-rsa-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01])
            .Attribute(CKA.CKA_ENCAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
            // C_DecapsulateKey for RSA-OAEP is equivalent to C_UnwrapKey (PKCS#11 v3.2 §5.18.11);
            // opencryptoki's key_mgr_unwrap_key only allows CKA_VALUE_LEN in the unwrapping
            // template for a handful of block-cipher mechanisms, rejecting it for
            // CKM_RSA_PKCS_OAEP with CKR_TEMPLATE_INCONSISTENT. The decapsulated length is
            // already fully determined by the OAEP-decrypted plaintext.
            AssertRoundTrips(key, mechanism, backend.SupportsTokenObjects, valueLenOnDecapsulate: false);
        }
        finally
        {
            key.Destroy();
        }
    }

    internal static void Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(IPkcs11Backend backend)
    {
        RequireEncapsulation(backend, CKM.CKM_ECDH1_DERIVE);
        using var session = OpenSession(backend);
        // Reading the shared secret back to compare is the extract-and-destroy path, gated by the
        // secure-defaults policy.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);

        string label = $"encap-ecdh-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams())
            .Attribute(CKA.CKA_ENCAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            // pPublicData must be empty for this call shape (PKCS#11 v3.2 §5.18.10/.11): the token
            // generates its own ephemeral EC key pair internally against this key's curve.
            var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_SHA256_KDF));
            AssertRoundTrips(key, mechanism, backend.SupportsTokenObjects);
        }
        finally
        {
            key.Destroy();
        }
    }

    public static TheoryData<CkpMlKem> MlKemParameterSets =>
    [
        CkpMlKem.CKP_ML_KEM_512,
        CkpMlKem.CKP_ML_KEM_768,
        CkpMlKem.CKP_ML_KEM_1024,
    ];

    // The path consumers should take: C_EncapsulateKey / C_DecapsulateKey straight into a sensitive,
    // non-extractable AES-256 key, under the session's default policy (no AllowInsecure lease, since nothing
    // is read off the token). The two sides agree when one key decrypts what the other encrypted, so the test
    // never needs the secret's bytes, and it checks that the token keeps them unreadable.
    // tokenKeepsSensitive: false pins a token that drops the template's CKA_SENSITIVE = TRUE on the shared key
    // (BouncyHsm). The case then asserts the value is readable, so it fails, and the pin can go, once fixed.
    internal static void Assert_MlKem_EncapsulateDecapsulate_ToNonExtractableAesKey(
        IPkcs11Backend backend, CkpMlKem parameterSet, bool tokenKeepsSensitive = true)
    {
        MLKemAlgorithm algorithm = parameterSet switch
        {
            CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
            CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
            CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet)),
        };
        backend.RequireMlKemParameterSet(algorithm.EncapsulationKeySizeInBytes);
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        using var session = OpenSession(backend);

        string label = $"encap-mlkem-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            AssertRoundTripsToNonExtractableAesKey(
                key, new Mechanism(CKM.CKM_ML_KEM), algorithm.CiphertextSizeInBytes, tokenKeepsSensitive);
        }
        finally
        {
            key.Destroy();
        }
    }

    // The keys C_EncapsulateKey and C_DecapsulateKey make have no protected history: PKCS#11 v3.2 §5.18.8 and
    // §5.18.9 set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE to FALSE on them, as on an unwrapped key, since the
    // shared secret's bytes exist outside the token, however the template protects it. The template's usage flags
    // are kept: CKA_ENCRYPT and CKA_DECRYPT read TRUE. ML-KEM-768. Skips a token that does not report both history
    // attributes.
    internal static void Assert_EncapsulatedKeys_HaveNoProtectedHistory(IPkcs11Backend backend)
    {
        backend.RequireMlKemParameterSet(MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes);
        using var session = OpenSession(backend);

        string label = $"encap-history-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ML_KEM);
            using var encTemplate = AesSharedKeyTemplate(32, valueLen: true);
            var (ciphertext, encKey) = key.EncapsulateKey(mechanism, encTemplate, MLKemAlgorithm.MLKem768.CiphertextSizeInBytes);
            try
            {
                using Pkcs11Key decKey = DecapsulateAesKey(key, mechanism, ciphertext, 32);
                try
                {
                    AssertNoProtectedHistory(encKey, "encapsulated");
                    AssertNoProtectedHistory(decKey, "decapsulated");
                    AssertStaysOnToken(encKey, tokenKeepsSensitive: true);
                    AssertStaysOnToken(decKey, tokenKeepsSensitive: true);
                }
                finally
                {
                    decKey.Destroy();
                }
            }
            finally
            {
                using (encKey) { encKey.Destroy(); }
            }
        }
        finally
        {
            key.Destroy();
        }
    }

    private static void AssertNoProtectedHistory(Pkcs11Key sharedKey, string side)
    {
        using var attrs = sharedKey.GetAttributeValue(
            CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            Assert.Skip("The backend does not report CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE.");
        Assert.False(attrs[0].GetValueAsBool(), $"The {side} key is CKA_ALWAYS_SENSITIVE.");
        Assert.False(attrs[1].GetValueAsBool(), $"The {side} key is CKA_NEVER_EXTRACTABLE.");
        Assert.True(attrs[2].GetValueAsBool(), $"The {side} key lost the template's CKA_ENCRYPT.");
        Assert.True(attrs[3].GetValueAsBool(), $"The {side} key lost the template's CKA_DECRYPT.");
    }

    public static TheoryData<string> MontgomeryCurves => ["X25519", "X448"];

    // The same on-token round trip as ML-KEM's, with CKM_ECDH1_DERIVE on a Montgomery key pair: the token
    // generates the ephemeral key against the recipient's curve (pPublicData empty, PKCS#11 v3.2 §5.18.10) and
    // the ciphertext is its public key. A token may give Montgomery keys an encapsulation path of their own
    // (BouncyHsm does), separate from the P-256 one Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips covers.
    // tokenKeepsSensitive: as for the ML-KEM case.
    internal static void Assert_Ecdh1Montgomery_EncapsulateDecapsulate_ToNonExtractableAesKey(
        IPkcs11Backend backend, string curve, bool tokenKeepsSensitive = true)
    {
        byte oid = curve switch
        {
            "X25519" => 0x6E,
            "X448" => 0x6F,
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, null),
        };
        backend.RequireMechanism(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        RequireEncapsulation(backend, CKM.CKM_ECDH1_DERIVE);
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        using var session = OpenSession(backend);

        string label = $"encap-{curve.ToLowerInvariant()}-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC_MONTGOMERY)
            .Label(label).Id(id).EcParams([0x06, 0x03, 0x2B, 0x65, oid])
            .Attribute(CKA.CKA_ENCAPSULATE, true).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC_MONTGOMERY)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_SHA256_KDF));
            AssertRoundTripsToNonExtractableAesKey(key, mechanism, expectedCiphertextLength: 0, tokenKeepsSensitive);
        }
        finally
        {
            key.Destroy();
        }
    }

    // Encapsulates to, and decapsulates from, key into AES-256 shared keys that must stay on the token, and checks
    // that the two agree: AES-GCM under one decrypts under the other. expectedCiphertextLength 0 checks no length.
    private static void AssertRoundTripsToNonExtractableAesKey(
        Pkcs11Key key, Mechanism mechanism, int expectedCiphertextLength, bool tokenKeepsSensitive)
    {
        const int SharedKeyLength = 32;
        using var encTemplate = AesSharedKeyTemplate(SharedKeyLength, valueLen: true);
        var (ciphertext, encKey) = key.EncapsulateKey(mechanism, encTemplate, expectedCiphertextLength);
        try
        {
            if (expectedCiphertextLength != 0)
                Assert.Equal(expectedCiphertextLength, ciphertext.Length);
            using Pkcs11Key decKey = DecapsulateAesKey(key, mechanism, ciphertext, SharedKeyLength);
            try
            {
                AssertStaysOnToken(encKey, tokenKeepsSensitive);
                AssertStaysOnToken(decKey, tokenKeepsSensitive);

                byte[] iv = RandomNumberGenerator.GetBytes(12);
                byte[] plaintext = "shared secret, kept on the token"u8.ToArray();
                byte[] sealedData = encKey.Encrypt(AesGcm(iv), plaintext);
                Assert.Equal(plaintext, decKey.Decrypt(AesGcm(iv), sealedData));
            }
            finally
            {
                decKey.Destroy();
            }
        }
        finally
        {
            using (encKey) { encKey.Destroy(); }
        }
    }

    private static ObjectTemplate AesSharedKeyTemplate(int length, bool valueLen)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES).OnToken(false).Sensitive().NonExtractable().Encrypt().Decrypt();
        if (valueLen)
            builder = builder.ValueLen(length);
        return builder.Build();
    }

    // Decapsulation creates the key with unwrap semantics: SoftHSM treats CKA_VALUE_LEN as read-only there,
    // where opencryptoki requires it, so try with it and fall back without, as MLKemPkcs11 does.
    private static Pkcs11Key DecapsulateAesKey(Pkcs11Key key, Mechanism mechanism, byte[] ciphertext, int length)
    {
        try
        {
            using var template = AesSharedKeyTemplate(length, valueLen: true);
            return key.DecapsulateKey(mechanism, ciphertext, template);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            using var template = AesSharedKeyTemplate(length, valueLen: false);
            return key.DecapsulateKey(mechanism, ciphertext, template);
        }
    }

    private static void AssertStaysOnToken(Pkcs11Key sharedKey, bool tokenKeepsSensitive)
    {
        using var attrs = sharedKey.GetAttributeValue(CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_VALUE);
        Assert.False(attrs[1].GetValueAsBool(), "the shared-secret key should not be CKA_EXTRACTABLE");
        if (!tokenKeepsSensitive)
        {
            Assert.False(attrs[0].GetValueAsBool(), "the token now keeps CKA_SENSITIVE on the shared-secret key: drop its pin");
            Assert.False(attrs[2].CannotBeRead, "the token now hides the shared-secret key's CKA_VALUE: drop its pin");
            return;
        }
        Assert.True(attrs[0].GetValueAsBool(), "the shared-secret key should be CKA_SENSITIVE");
        Assert.True(attrs[2].CannotBeRead, "the token returned the shared-secret key's CKA_VALUE");
    }

    private static Mechanism AesGcm(byte[] iv) => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128));
}
