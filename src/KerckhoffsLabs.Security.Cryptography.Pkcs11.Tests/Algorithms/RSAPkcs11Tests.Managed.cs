using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RSAPkcs11 over the in-process <c>ManagedSoftToken</c>: generate an RSA-2048 key pair on the token,
/// sign + verify on-token (PKCS#1 v1.5 and PSS, hash+sign combined mechanisms), and confirm the
/// exported public key verifies the same signature in the BCL. Exercises C_GenerateKeyPair (RSA).
/// </summary>
public sealed class RSAPkcs11Tests_Managed
{
    public static TheoryData<string> Paddings => ["Pkcs1", "Pss"];

    [Theory]
    [MemberData(nameof(Paddings))]
    public void SignVerify_RoundTrips_AndPublicMatchesBcl(string paddingName)
    {
        var padding = paddingName == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var key = workspace.GenerateRsaKeyPair(modulusBits: 2048);
        using var rsa = new RSAPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("RSA signed on a managed token");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, padding);

        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, padding));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256, padding));

        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);
        using var bcl = RSA.Create(pub);
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, padding));
    }
}
