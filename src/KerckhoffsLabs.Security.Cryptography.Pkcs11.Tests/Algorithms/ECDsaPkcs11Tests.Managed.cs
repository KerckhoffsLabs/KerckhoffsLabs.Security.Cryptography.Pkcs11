using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDsaPkcs11 over the in-process <c>ManagedSoftToken</c>: generate an EC key pair on the token,
/// sign + verify on-token, and confirm the exported public point verifies the same signature in the
/// BCL. Exercises C_GenerateKeyPair (EC) and the raw-r‖s ECDSA sign/verify path end-to-end.
/// </summary>
public sealed class ECDsaPkcs11Tests_Managed
{
    [Theory]
    [InlineData(EcCurve.P256)]
    [InlineData(EcCurve.P384)]
    public void SignVerify_RoundTrips_AndPublicMatchesBcl(EcCurve curve)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var key = workspace.GenerateEcKeyPair(curve);
        using var ecdsa = new ECDsaPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("signed on a managed token, verified by the BCL");
        byte[] sig = ecdsa.SignData(data, HashAlgorithmName.SHA256);

        // On-token verify (C_Verify over the public handle).
        Assert.True(ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(ecdsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256));

        // The exported public point (CKA_EC_POINT) must verify the same signature in the BCL.
        ECParameters pub = ecdsa.ExportParameters(includePrivateParameters: false);
        using var bcl = ECDsa.Create(pub);
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256));
    }
}
