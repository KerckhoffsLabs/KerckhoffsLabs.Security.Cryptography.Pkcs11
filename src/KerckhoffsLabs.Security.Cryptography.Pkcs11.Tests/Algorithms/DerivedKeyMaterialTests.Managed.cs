using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <c>DerivedKeyMaterial.DeriveAndRead</c>, the read-back shared by the byte-returning KDF adapters,
/// over the managed token and reached through <see cref="SP800108HmacCounterKdfPkcs11"/>. Covers the
/// ephemeral key's cleanup and which exception surfaces when reading or destroying it fails.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class DerivedKeyMaterial_Managed
{
    // Distinct from any length the base key carries, so a CKA_VALUE_LEN filter finds only derived keys.
    private const int OutputLength = 24;

    private static readonly byte[] KeyBytes =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    private static void WithKdf(Action<ManagedSoftToken, Pkcs11Workspace, SP800108HmacCounterKdfPkcs11> body)
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure); // reading derived bytes back is gated
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf").Value(KeyBytes).Derive().Build();
        using var key = workspace.ImportKey(tpl);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);
        try
        {
            body(token, workspace, kdf);
        }
        finally
        {
            token.DeriveWithholdsValue = false;
            token.DestroyObjectResultOverride = null;
        }
    }

    private static byte[] Derive(SP800108HmacCounterKdfPkcs11 kdf) =>
        kdf.DeriveKey("label"u8.ToArray(), "context"u8.ToArray(), OutputLength);

    private static int DerivedKeysOnToken(Pkcs11Workspace workspace)
    {
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_VALUE_LEN, (ulong)OutputLength).Build();
        using var found = workspace.FindObjects(filter);
        return found.Count;
    }

    [Fact]
    public void DeriveAndRead_ReturnsTheValue_AndDestroysTheEphemeralKey() => WithKdf((_, workspace, kdf) =>
    {
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, "label"u8, "context"u8, OutputLength);

        Assert.Equal(expected, Derive(kdf));
        Assert.Equal(0, DerivedKeysOnToken(workspace));
    });

    /// <summary>
    /// A token that keeps the derived value on-token whatever the template asked for must fail the
    /// call, not hand back an empty array as if it were key material; the key is still cleaned up.
    /// </summary>
    [Fact]
    public void DeriveAndRead_WhenTheValueIsWithheld_Throws_AndDestroysTheEphemeralKey() => WithKdf((token, workspace, kdf) =>
    {
        token.DeriveWithholdsValue = true;

        var ex = Assert.Throws<InvalidOperationException>(() => Derive(kdf));
        Assert.Contains("CKA_VALUE", ex.Message);
        Assert.Equal(0, DerivedKeysOnToken(workspace));
    });

    /// <summary>
    /// When the read already failed, a failing cleanup must not replace that exception: the caller
    /// needs to learn the value was withheld, not that <c>C_DestroyObject</c> failed afterwards.
    /// </summary>
    [Fact]
    public void DeriveAndRead_WhenTheReadAndTheDestroyBothFail_SurfacesTheReadFailure() => WithKdf((token, _, kdf) =>
    {
        token.DeriveWithholdsValue = true;
        token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;

        Assert.Throws<InvalidOperationException>(() => Derive(kdf));
    });

    /// <summary>
    /// When the read succeeded, the failed destroy is the only thing that went wrong, so it surfaces
    /// rather than being swallowed with the derived key left on the token.
    /// </summary>
    [Fact]
    public void DeriveAndRead_WhenOnlyTheDestroyFails_SurfacesTheDestroyFailure() => WithKdf((token, workspace, kdf) =>
    {
        token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Derive(kdf));
        Assert.Equal(CKR.CKR_FUNCTION_FAILED, ex.ReturnValue);
        Assert.Equal(1, DerivedKeysOnToken(workspace));
    });
}
