using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable CS0618 // TripleDESPkcs11 is [Obsolete] — exercised intentionally.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>TripleDESPkcs11 over the in-process <c>ManagedSoftToken</c> (no SoftHSM). Key is generated
/// by the BCL <see cref="TripleDES"/> (guaranteed non-weak) then imported.</summary>
public sealed class TripleDESPkcs11Tests_Managed
{
    [Fact]
    public void Cbc_Pkcs7_MatchesBclTripleDes_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        workspace.AllowInsecure = true;

        using var bcl = TripleDES.Create();
        byte[] keyBytes = bcl.Key;

        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES3)
            .Label("des3").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var des3 = new TripleDESPkcs11(key);

        byte[] iv = RandomNumberGenerator.GetBytes(8);
        byte[] plaintext = RandomNumberGenerator.GetBytes(40);

        byte[] ct = des3.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        Assert.Equal(bcl.EncryptCbc(plaintext, iv, PaddingMode.PKCS7), ct);
        Assert.Equal(plaintext, des3.DecryptCbc(ct, iv, PaddingMode.PKCS7));
    }
}
