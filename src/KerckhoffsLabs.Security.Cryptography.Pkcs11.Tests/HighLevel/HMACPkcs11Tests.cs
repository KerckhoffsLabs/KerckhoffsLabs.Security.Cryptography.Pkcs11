using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class HMACPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new HMACPkcs11(key: null!, HashAlgorithmName.SHA256));
}

[Collection("SoftHsm")]
public sealed class HMACPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public HMACPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Sha256_DeterministicForSameKeyAndInput()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"hmac-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().Verify().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

            byte[] data = System.Text.Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(32, mac1.Length);
            Assert.Equal(mac1, mac2);
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }
}
