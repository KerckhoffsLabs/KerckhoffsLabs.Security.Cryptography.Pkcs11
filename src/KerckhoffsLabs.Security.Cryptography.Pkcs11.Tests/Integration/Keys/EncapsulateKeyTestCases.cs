using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
/// SoftHSM2 implement key encapsulation for ML-KEM only, so their test files skip everything here.
/// </summary>
internal static class EncapsulateKeyTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) => backend.OpenWorkspace();

    private static ObjectTemplate SharedSecretTemplate(bool onToken) =>
        ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(32).Extractable().Sensitive(false).OnToken(onToken).Build();

    private static void AssertRoundTrips(Pkcs11Key key, Mechanism mechanism, bool onToken)
    {
        using var encTemplate = SharedSecretTemplate(onToken);
        var (ciphertext, encSecret) = key.EncapsulateKey(mechanism, encTemplate);
        try
        {
            using var decTemplate = SharedSecretTemplate(onToken);
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
        using var workspace = OpenWorkspace(backend);
        // Reading the shared secret back to compare is the extract-and-destroy path, gated by the
        // secure-defaults policy.
        workspace.AllowInsecure = true;

        string label = $"encap-rsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01])
            .Attribute(CKA.CKA_ENCAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
            AssertRoundTrips(key, mechanism, backend.SupportsTokenObjects);
        }
        finally
        {
            key.Destroy();
        }
    }

    internal static void Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // Reading the shared secret back to compare is the extract-and-destroy path, gated by the
        // secure-defaults policy.
        workspace.AllowInsecure = true;

        string label = $"encap-ecdh-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams())
            .Attribute(CKA.CKA_ENCAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).OnToken(backend.SupportsTokenObjects).Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
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
}
