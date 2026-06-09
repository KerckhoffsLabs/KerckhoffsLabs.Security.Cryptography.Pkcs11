using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDH (P-256, CKD_NULL) against the second real backend (opencryptoki): the raw shared secret a
/// token key derives against a BCL peer must equal the secret the BCL derives against the token's
/// public key.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class ECDiffieHellmanPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private void Require(params CKM[] mechanisms)
    {
        foreach (var m in mechanisms)
            if (!_backend.Supports(m))
                throw new SkipTestException($"opencryptoki: {m} not available");
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithEcdh(Action<ECDiffieHellmanPkcs11> body)
    {
        Require(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE);
        using var workspace = OpenWorkspace();
        string label = $"octk-ecdh-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).EcParams(TestKeys.EcP256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Derive().Build();
        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var ecdh = new ECDiffieHellmanPkcs11(key);
            body(ecdh);
        }
        finally
        {
            try { DestroyByLabel(workspace, label); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalFact(nameof(Available))]
    public void DeriveRawSecretAgreement_MatchesBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);
        Assert.Equal(bobZ, aliceZ);
    });
}
