using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("WolfPkcs11")]
public sealed class Pkcs11KeyPublicSynthesisTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Rsa_PrivateOnly_HasSynthesizedPublicView()
    {
        using var session = OpenSession();

        string label = $"rsa-test-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01])
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign()
            .Build();

        session.Core.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes],
            [.. privTpl.Attributes],
            out var pubHandle,
            out var privHandle);

        try
        {
            // Destroy the public-key object so only the private-side survives.
            session.Core.DestroyObject(pubHandle);

            // Now OpenKey by label — it should find ONLY the private and synthesize the public view.
            using var key = session.OpenKey(label);

            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.True(key.PublicHandle.IsInvalid); // no CKO_PUBLIC_KEY companion left

            var rsaParams = key.GetSynthesizedRsaParameters();
            Assert.NotNull(rsaParams);
            Assert.Equal(2048 / 8, rsaParams!.Value.Modulus!.Length);
        }
        finally
        {
            session.Core.DestroyObject(privHandle);
        }
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Rsa_PrivateOnly_ManagedVerify_Pkcs1AndPss_RoundTrip()
    {
        using var session = OpenSession();
        string label = $"rsa-managedverify-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        session.Core.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes], [.. privTpl.Attributes],
            out var pubHandle, out var privHandle);
        try
        {
            session.Core.DestroyObject(pubHandle); // leave only the private-side
            using var key = session.OpenKey(label);
            Assert.True(key.PublicHandle.IsInvalid);

            using var rsa = new RSAPkcs11(key);
            byte[] data = Encoding.UTF8.GetBytes("managed verify over a private-only RSA key");
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;

            // RSA-PSS: signed on the token, verified in managed code via synthesized public params.
            byte[] pss = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(rsa.VerifyData(data, pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            Assert.False(rsa.VerifyData(tampered, pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            // PKCS#1 v1.5: still works through the same managed path.
            byte[] pkcs1 = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyData(data, pkcs1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.False(rsa.VerifyData(tampered, pkcs1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        finally
        {
            session.Core.DestroyObject(privHandle);
        }
    }

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
}
