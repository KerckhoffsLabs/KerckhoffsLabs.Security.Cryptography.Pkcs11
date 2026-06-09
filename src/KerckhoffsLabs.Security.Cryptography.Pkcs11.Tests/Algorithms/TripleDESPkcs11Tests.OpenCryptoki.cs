using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32); the secure-defaults gate is the point of
// the type, so CS0618 is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>
/// 3DES-CBC against the second real backend (opencryptoki), cross-checked against the BCL. Every mode
/// is gated by the secure-defaults policy, so this opts in via AllowInsecure.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class TripleDESPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private static readonly byte[] Key192 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithImportedDes3(Action<Pkcs11Workspace, TripleDESPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_DES3_CBC))
            throw new SkipTestException("opencryptoki: CKM_DES3_CBC not available");

        using var workspace = OpenWorkspace();
        string label = $"octk-des3-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES3)
            .Label(label).Value(Key192).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var des3 = new TripleDESPkcs11(key);
            body(workspace, des3);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(Available))]
    public void EncryptCbc_Pkcs7_UnderAllowInsecure_MatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("3DES-CBC over an opencryptoki token key — variable length.");

        workspace.AllowInsecure = true;
        using var bcl = TripleDES.Create();
        bcl.Key = Key192;

        byte[] ct = des3.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
        Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
    });
}
#pragma warning restore CS0618
