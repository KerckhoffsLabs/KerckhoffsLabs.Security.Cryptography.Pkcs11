using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

internal static class Pkcs11KeyMechanismCases
{
    public static void Assert_RsaSignVerify_RoundTrips(Pkcs11Workspace workspace)
    {
        string label = $"sign-verify-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello pkcs11");

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 }).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            using var key = workspace.OpenKey(label);
            var sha256Rsa = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);

            byte[] signature = key.Sign(sha256Rsa, data);
            Assert.True(key.Verify(sha256Rsa, data, signature));

            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;
            Assert.False(key.Verify(sha256Rsa, tampered, signature));
        }
        finally
        {
            workspace.Session.DestroyObject(pubHandle);
            workspace.Session.DestroyObject(privHandle);
        }
    }
}

[Collection("SoftHsm")]
public sealed class Pkcs11KeyMechanismTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11KeyMechanismTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(workspace);
    }
}
