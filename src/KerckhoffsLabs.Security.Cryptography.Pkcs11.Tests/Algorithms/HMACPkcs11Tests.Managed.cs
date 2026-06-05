using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HMACPkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM.</summary>
public sealed class HMACPkcs11Tests_Managed
{
    private static Pkcs11Key ImportHmacKey(Pkcs11Workspace workspace, byte[] keyBytes)
    {
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label($"hmac-{Guid.NewGuid():N}").Value(keyBytes).Sign().Verify().Build();
        return workspace.ImportKey(tpl);
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void ComputeHash_MatchesBclHmac_OverManagedToken(string hashName)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var key = ImportHmacKey(workspace, keyBytes);
        var alg = new HashAlgorithmName(hashName);
        using var hmac = new HMACPkcs11(key, alg);

        byte[] data = Encoding.UTF8.GetBytes("authenticated by a managed-token HMAC");
        byte[] expected = hashName switch
        {
            "SHA256" => HMACSHA256.HashData(keyBytes, data),
            "SHA384" => HMACSHA384.HashData(keyBytes, data),
            "SHA512" => HMACSHA512.HashData(keyBytes, data),
            _ => throw new InvalidOperationException(),
        };

        Assert.Equal(expected, hmac.ComputeHash(data));
    }
}
