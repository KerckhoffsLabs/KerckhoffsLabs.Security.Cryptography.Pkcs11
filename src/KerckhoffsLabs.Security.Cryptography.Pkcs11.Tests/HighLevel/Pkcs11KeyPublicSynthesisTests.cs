using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("SoftHsm")]
public sealed class Pkcs11KeyPublicSynthesisTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11KeyPublicSynthesisTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Rsa_PrivateOnly_HasSynthesizedPublicView()
    {
        using var workspace = OpenWorkspace();

        string label = $"rsa-test-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 })
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign()
            .Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            // Destroy the public-key object so only the private-side survives.
            workspace.Session.DestroyObject(pubHandle);

            // Now OpenKey by label — it should find ONLY the private and synthesize the public view.
            using var key = workspace.OpenKey(label);

            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.True(key.PublicHandle.IsInvalid); // no CKO_PUBLIC_KEY companion left

            var rsaParams = key.GetSynthesizedRsaParameters();
            Assert.NotNull(rsaParams);
            Assert.Equal(2048 / 8, rsaParams!.Value.Modulus!.Length);
        }
        finally
        {
            workspace.Session.DestroyObject(privHandle);
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ec_PrivateOnly_SynthesizesWhenEcPointPresent()
    {
        using var workspace = OpenWorkspace();

        string label = $"ec-test-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        // OID for secp256r1 (NIST P-256), DER-encoded.
        byte[] secp256r1 = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(secp256r1).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            workspace.Session.DestroyObject(pubHandle);
            using var key = workspace.OpenKey(label);
            var ec = key.GetSynthesizedEcParameters();
            // On SoftHSM, CKA_EC_POINT is stored on the private key, so synthesis succeeds.
            Assert.NotNull(ec);
            Assert.NotNull(ec!.Value.Q.X);
        }
        finally
        {
            workspace.Session.DestroyObject(privHandle);
        }
    }
}
