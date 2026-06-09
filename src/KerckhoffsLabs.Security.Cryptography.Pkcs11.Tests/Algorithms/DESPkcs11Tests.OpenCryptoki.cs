using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// DESPkcs11 is [Obsolete] (56-bit key); the secure-defaults gate is the point of the type, so CS0618
// is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>
/// Single-DES CBC against the second real backend (opencryptoki), which (unlike a FIPS-built SoftHSM)
/// implements CKM_DES_CBC. Cross-checked against the BCL; gated by the secure-defaults policy.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class DESPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private static readonly byte[] Key64 = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithImportedDes(Action<Pkcs11Workspace, DESPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_DES_CBC))
            throw new SkipTestException("opencryptoki: CKM_DES_CBC not available");

        using var workspace = OpenWorkspace();
        string label = $"octk-des-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES)
            .Label(label).Value(Key64).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var des = new DESPkcs11(key);
            body(workspace, des);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(Available))]
    public void EncryptCbc_Pkcs7_UnderAllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("DES-CBC over an opencryptoki token key — variable length.");

        workspace.AllowInsecure = true;
        using var bcl = DES.Create();
        bcl.Key = Key64;

        byte[] ct;
        try
        {
            ct = des.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_INVALID)
        {
            throw new SkipTestException("opencryptoki advertises but does not implement CKM_DES_CBC.");
        }
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
        Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8));
    });
}
#pragma warning restore CS0618
