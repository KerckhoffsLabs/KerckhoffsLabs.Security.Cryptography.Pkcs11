using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
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
}
