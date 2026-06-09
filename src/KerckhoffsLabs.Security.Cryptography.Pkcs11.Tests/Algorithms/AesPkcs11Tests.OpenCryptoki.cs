using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AES-CBC against the second real backend (opencryptoki), cross-checked against the BCL for the same
/// imported key. CBC is unauthenticated and gated by the secure-defaults policy, so it needs AllowInsecure.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class AesPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    private void Require(CKM mechanism)
    {
        if (!_backend.Supports(mechanism))
            throw new SkipTestException($"opencryptoki: {mechanism} not available");
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithImportedAes(Action<Pkcs11Workspace, AesPkcs11> body)
    {
        Require(CKM.CKM_AES_CBC);
        using var workspace = OpenWorkspace();
        string label = $"octk-aes-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(Key256).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var aes = new AesPkcs11(key);
            body(workspace, aes);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(Available))]
    public void EncryptCbc_Pkcs7_UnderAllowInsecure_MatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-CBC over an opencryptoki token key — variable length.");

        workspace.AllowInsecure = true;
        using var bcl = Aes.Create();
        bcl.Key = Key256;

        byte[] ct = aes.EncryptCbc(plaintext, Iv16); // default PaddingMode.PKCS7
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv16), ct);
        Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
    });
}
