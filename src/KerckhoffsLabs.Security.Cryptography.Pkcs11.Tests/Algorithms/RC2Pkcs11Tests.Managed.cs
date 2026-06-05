using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable CS0618 // RC2Pkcs11 is [Obsolete] — exercised intentionally.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RC2Pkcs11 over the in-process <c>ManagedSoftToken</c>. RC2 is gated on two fronts: the
/// secure-defaults policy (→ <c>AllowInsecure</c>) and the BCL, whose <see cref="RC2"/> implementation
/// is Windows-only — so this runs only on Windows, mirroring how SoftHSM also lacks RC2.
/// </summary>
public sealed class RC2Pkcs11Tests_Managed
{
    public static bool Rc2Supported => OperatingSystem.IsWindows();

    [ConditionalFact(nameof(Rc2Supported))]
    public void Cbc_Pkcs7_MatchesBclRc2_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        workspace.AllowInsecure = true;

        using var bcl = RC2.Create();
        byte[] keyBytes = bcl.Key;
        int effectiveBits = bcl.EffectiveKeySize;

        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_RC2)
            .Label("rc2").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var rc2 = new RC2Pkcs11(key) { EffectiveKeySize = effectiveBits };

        byte[] iv = RandomNumberGenerator.GetBytes(8);
        byte[] plaintext = RandomNumberGenerator.GetBytes(24);

        byte[] ct = rc2.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        Assert.Equal(bcl.EncryptCbc(plaintext, iv, PaddingMode.PKCS7), ct);
        Assert.Equal(plaintext, rc2.DecryptCbc(ct, iv, PaddingMode.PKCS7));
    }
}
