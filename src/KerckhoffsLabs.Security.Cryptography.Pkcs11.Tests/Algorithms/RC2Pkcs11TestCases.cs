using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// RC2Pkcs11 is [Obsolete] (weak legacy cipher); the secure-defaults gate is the point of the type, so
// KLPKCS11005 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11005

/// <summary>
/// Backend-agnostic RC2Pkcs11 tests. The non-RC2-key constructor check only needs an AES key, so it
/// runs anywhere; every test that needs a token-resident RC2 key skips where the backend lacks
/// <c>CKM_RC2_CBC</c> (SoftHSM and opencryptoki do not implement RC2). Known-answer round-trips compare
/// against the BCL <see cref="RC2"/> for the same key, IV and effective key size.
/// </summary>
internal static class RC2Pkcs11TestCases
{
    private static readonly byte[] Key128 = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");
    private const int EffectiveBits = 128;

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Imports Key128 as a token RC2 key and hands a wrapping RC2Pkcs11 (and its workspace) to the body.
    // Skips where the backend does not implement RC2.
    private static void WithImportedRc2(IPkcs11Backend backend, Action<Pkcs11Workspace, RC2Pkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_RC2_CBC))
            throw new SkipTestException("Backend does not advertise CKM_RC2_CBC.");

        using var workspace = OpenWorkspace(backend);
        string label = $"rc2-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_RC2)
            .Label(label).Value(Key128).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var rc2 = new RC2Pkcs11(key) { EffectiveKeySize = EffectiveBits };
            body(workspace, rc2);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static RC2 BclRc2()
    {
        var bcl = RC2.Create();
        bcl.Key = Key128;
        bcl.EffectiveKeySize = EffectiveBits;
        return bcl;
    }

    internal static void Assert_Ctor_NonRc2Key_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"nonrc2-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(16).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new RC2Pkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (_, rc2) =>
            Assert.Throws<InsecureOperationException>(() => rc2.EncryptCbc(new byte[8], Iv8)));

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (_, rc2) =>
            Assert.Throws<InsecureOperationException>(() => rc2.EncryptEcb(new byte[8], PaddingMode.None)));

    internal static void Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (workspace, rc2) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("RC2-CBC PKCS7 over a token key.");
            workspace.AllowInsecure = true;
            using var bcl = BclRc2();

            byte[] ct = rc2.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
            Assert.Equal(plaintext, rc2.DecryptCbc(ct, Iv8));
        });

    internal static void Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (workspace, rc2) =>
        {
            byte[] plaintext = new byte[16]; // two 8-byte blocks
            RandomNumberGenerator.Fill(plaintext);
            workspace.AllowInsecure = true;
            using var bcl = BclRc2();

            byte[] ct = rc2.EncryptCbc(plaintext, Iv8, PaddingMode.None);
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
            Assert.Equal(plaintext, rc2.DecryptCbc(ct, Iv8, PaddingMode.None));
        });

    internal static void Assert_EncryptEcb_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (workspace, rc2) =>
        {
            workspace.AllowInsecure = true;
            byte[] plaintext = new byte[8];
            RandomNumberGenerator.Fill(plaintext);
            using var bcl = BclRc2();

            byte[] ct = rc2.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, rc2.DecryptEcb(ct, PaddingMode.None));
        });

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (_, rc2) =>
            Assert.Throws<NotSupportedException>(() => rc2.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (_, rc2) =>
        {
            rc2.GenerateIV();
            Assert.Equal(8, rc2.IV.Length);
        });

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedRc2(backend, (_, rc2) =>
        {
            Assert.Throws<NotSupportedException>(() => rc2.CreateEncryptor(new byte[16], new byte[8]));
            Assert.Throws<NotSupportedException>(() => rc2.CreateDecryptor(new byte[16], new byte[8]));
            Assert.Throws<NotSupportedException>(() => rc2.GenerateKey());
            Assert.Throws<NotSupportedException>(() => rc2.Key);
        });
}
