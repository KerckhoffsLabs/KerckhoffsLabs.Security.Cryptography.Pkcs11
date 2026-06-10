using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// opencryptoki counterpart of Pkcs11KeyPublicSynthesisTests_SoftHsm: a private-only RSA key (no
/// CKO_PUBLIC_KEY companion) must still expose a synthesized public view (CKA_MODULUS +
/// CKA_PUBLIC_EXPONENT are stored on the RSA private object) and verify in managed code.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class Pkcs11KeyPublicSynthesisTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(Available))]
    public void Rsa_PrivateOnly_HasSynthesizedPublicView()
    {
        using var workspace = OpenWorkspace();

        string label = $"octk-rsa-synth-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes], [.. privTpl.Attributes],
            out var pubHandle, out var privHandle);

        try
        {
            workspace.Session.DestroyObject(pubHandle); // leave only the private-side

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

    [ConditionalFact(nameof(Available))]
    public void Rsa_PrivateOnly_ManagedVerify_Pkcs1AndPss_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        string label = $"octk-rsa-mverify-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes], [.. privTpl.Attributes],
            out var pubHandle, out var privHandle);
        try
        {
            workspace.Session.DestroyObject(pubHandle); // leave only the private-side
            using var key = workspace.OpenKey(label);
            Assert.True(key.PublicHandle.IsInvalid);

            using var rsa = new RSAPkcs11(key);
            byte[] data = Encoding.UTF8.GetBytes("managed verify over a private-only RSA key");
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;

            byte[] pss = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(rsa.VerifyData(data, pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            Assert.False(rsa.VerifyData(tampered, pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            byte[] pkcs1 = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyData(data, pkcs1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.False(rsa.VerifyData(tampered, pkcs1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        finally
        {
            workspace.Session.DestroyObject(privHandle);
        }
    }
}
