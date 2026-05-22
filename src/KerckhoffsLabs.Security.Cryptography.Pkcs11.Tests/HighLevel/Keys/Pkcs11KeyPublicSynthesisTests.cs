using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

[Collection("SoftHsm")]
public sealed class Pkcs11KeyPublicSynthesisTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

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
            .PublicExponent([0x01, 0x00, 0x01])
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign()
            .Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes],
            [.. privTpl.Attributes],
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

    // Note: a previous Ec_PrivateOnly_SynthesizesWhenEcPointPresent test lived here and
    // assumed CKA_EC_POINT was readable from a CKO_PRIVATE_KEY object. SoftHSM 2.x stores
    // only CKA_EC_PARAMS + CKA_VALUE on the EC private object (see vendor/softhsmv2
    // P11Objects.cpp P11ECPrivateKeyObj::init), and PKCS#11 v2.40 places CKA_EC_POINT on
    // public objects only. Synthesizing the public point from a private-only object would
    // require either reading the (sensitive) private scalar or doing an on-token point
    // multiplication — neither of which the library can do without compromising the
    // non-extractable posture. The RSA-equivalent test passes because CKA_MODULUS and
    // CKA_PUBLIC_EXPONENT are stored on RSA private objects.
}
