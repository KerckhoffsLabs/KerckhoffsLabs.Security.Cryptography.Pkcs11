using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Cases taken from bugs the backends fixed in their own history, run against every backend so a regression
/// in either a backend or this library shows up here.
/// </summary>
internal static class BackendRegressionTestCases
{
    // A P-256 pair whose shared secret Z starts with two zero bytes (found by search with the BCL).
    private static readonly byte[] LeadingZeroPrivate = Convert.FromHexString(
        "FD9790B8A5E17FA13A3062A4B5CF945E92EE67ED0601D3C930E56CD3B5961A4B");
    private static readonly byte[] LeadingZeroPeer = Convert.FromHexString(
        "3059301306072A8648CE3D020106082A8648CE3D030107034200046B6FADB501DCBC1943073599C4AEB7B2051E216C90ADE8" +
        "A6AE7ACC0DAC757B4D62AA83E75C3C3E653B76CF977F3E2EB6438C504C52DC17F3B2D33709665568C7");
    private static readonly byte[] LeadingZeroSecret = Convert.FromHexString(
        "0000F8E8B5BE80017046BC5B6964623A8B1419FFD3AE4452185AF8E6AEE453E0");

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    /// <summary>
    /// SoftHSM2 8bc65b5 ("C_DeriveKey() error with leading zero bytes"): OpenSSL returned Z without its
    /// leading zeros, and the derive then failed as too short. Z is a field element, always the field size
    /// long; a shorter value would silently be a different secret.
    /// </summary>
    internal static void Assert_EcdhRawSecret_WithLeadingZeroBytes_KeepsThem(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_ECDH1_DERIVE);
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"ecdh-z0-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(Encoding.ASCII.GetBytes(label)).Derive()
            .Attribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid).Attribute(CKA.CKA_VALUE, LeadingZeroPrivate)
            .OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            Assert.Equal(LeadingZeroSecret, key.DeriveRawSecret(LeadingZeroPeer));
        }
        finally { DestroyByLabel(session, label); }
    }

    /// <summary>
    /// SoftHSM2 5a3466f / 9c5867a: an EC key handed to an RSA mechanism crashed the module before it checked
    /// the key type. It must be refused with an error, and the session must keep working.
    /// </summary>
    internal static void Assert_KeyOfAnotherType_ForTheMechanism_IsRefused_SessionReusable(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDSA_SHA256))
            Assert.Skip("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDSA_SHA256.");

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"mismatch-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Label(label).Id(id).Verify().EcParams(TestKeys.EcP256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            byte[] data = Encoding.ASCII.GetBytes("key type mismatch");
            Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), data));
            Assert.ThrowsAny<Pkcs11Exception>(() => key.Verify(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), data, new byte[256]));

            byte[] signature = key.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), data);
            Assert.True(key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA256), data, signature));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    /// <summary>
    /// SoftHSM2 dd63378, Kryoptic cd2e305 / 938de44, NSS 878395906: <c>C_GetAttributeValue</c> must process every
    /// entry of the template, filling the readable ones even when others are sensitive or do not apply.
    /// </summary>
    internal static void Assert_GetAttributeValue_MixedTemplate_FillsTheReadableEntries(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = backend.OpenSession();
        string label = $"mixed-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().Attribute(CKA.CKA_SENSITIVE, true)
            .OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            using var attrs = key.GetAttributeValue(CKA.CKA_LABEL, CKA.CKA_VALUE, CKA.CKA_MODULUS, CKA.CKA_VALUE_LEN);

            Assert.Equal(label, attrs[0].GetValueAsString());
            Assert.True(attrs[1].CannotBeRead, "A sensitive CKA_VALUE was readable.");
            Assert.True(attrs[2].CannotBeRead, "An AES key returned a CKA_MODULUS.");
            Assert.Equal(32UL, attrs[3].GetValueAsUlong());
        }
        finally { DestroyByLabel(session, label); }
    }

    /// <summary>
    /// Kryoptic 5f1e7e6 (GCM decrypt offset) and 4f200ab / 926417f (CCM): the classic, parameter-in-<c>C_EncryptInit</c>
    /// AEAD path, which the adapters only take when a module lacks the message API, checked against the BCL.
    /// </summary>
    internal static void Assert_AesGcm_ClassicParameters_MatchBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] aad = Encoding.ASCII.GetBytes("classic gcm aad");
        byte[] plaintext = RandomNumberGenerator.GetBytes(100);

        byte[] expected = new byte[plaintext.Length + 16];
        using (var bcl = new AesGcm(rawKey, 16))
            bcl.Encrypt(iv, plaintext, expected.AsSpan(0, plaintext.Length), expected.AsSpan(plaintext.Length), aad);

        using var session = backend.OpenSession();
        string label = $"gcm-classic-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            var mechanism = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, aad, tagBits: 128));

            Assert.Equal(expected, key.Encrypt(mechanism, plaintext));
            Assert.Equal(plaintext, key.Decrypt(mechanism, expected));
        }
        finally { DestroyByLabel(session, label); }
    }
}
