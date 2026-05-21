using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

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

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen)
    {
        var hash = new HashAlgorithmName(hashName);
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"hmac-{Guid.NewGuid():N}";
        // Size the key to the digest length: SoftHSM enforces a per-mechanism minimum HMAC
        // key size (CKR_KEY_SIZE_RANGE otherwise) — 32 bytes is too small for SHA-384/512.
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(expectedLen).Sign().Verify().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), [.. t.Attributes]);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var hmac = new HMACPkcs11(key, hash);

            byte[] data = System.Text.Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(expectedLen, mac1.Length);
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
