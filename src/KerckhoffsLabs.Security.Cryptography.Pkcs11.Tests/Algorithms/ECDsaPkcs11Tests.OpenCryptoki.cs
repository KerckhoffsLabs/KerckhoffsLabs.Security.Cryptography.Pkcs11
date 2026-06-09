using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDSA (P-256) against a second real backend (opencryptoki). Re-running sign/verify on an
/// independent module guards against a SoftHSM-and-wrapper-shared signature-encoding bug.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class ECDsaPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithEcDsaP256(Action<ECDsaPkcs11> body)
    {
        if (!(_backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDSA)))
            throw new SkipTestException("opencryptoki: EC key-pair generation / ECDSA not available");

        using var workspace = OpenWorkspace();
        string label = $"octk-ec-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        Pkcs11Key key;
        using (var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
                   .Label(label).Id(id).Verify().EcParams(TestKeys.EcP256Oid).Build())
        using (var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
                   .Label(label).Id(id).Sign().Build())
        {
            key = workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        }
        try
        {
            using var ec = new ECDsaPkcs11(key);
            body(ec);
        }
        finally
        {
            try { DestroyByLabel(workspace, label); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_P256_RoundTrips() => WithEcDsaP256(ec =>
    {
        byte[] data = Encoding.UTF8.GetBytes("cross-backend ecdsa payload");
        byte[] sig = ec.SignData(data, HashAlgorithmName.SHA256);

        Assert.True(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));

        data[0] ^= 0xFF;
        Assert.False(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));
    });
}
