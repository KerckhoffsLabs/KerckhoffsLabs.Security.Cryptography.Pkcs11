using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SP800108HmacCounterKdfPkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM does not implement
/// <c>CKM_SP800_108_COUNTER_KDF</c>, so its KAT skips — the managed token runs it, deriving via the BCL
/// <see cref="SP800108HmacCounterKdf"/> and checking byte-for-byte equality.
/// </summary>
public sealed class SP800108HmacCounterKdfPkcs11Tests_Managed
{
    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void DeriveKey_MatchesBcl_OverManagedToken(string hashName)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf").Value(keyBytes).Derive().Build();
        using var key = workspace.ImportKey(tpl);

        var alg = new HashAlgorithmName(hashName);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, alg);

        byte[] label = Encoding.UTF8.GetBytes("label");
        byte[] context = Encoding.UTF8.GetBytes("context-bytes");

        byte[] derived = kdf.DeriveKey(label, context, derivedKeyLengthInBytes: 48);
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(keyBytes, alg, label, context, 48);

        Assert.Equal(expected, derived);
    }
}
