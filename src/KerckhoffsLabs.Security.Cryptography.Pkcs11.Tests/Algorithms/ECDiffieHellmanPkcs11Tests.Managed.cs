using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDiffieHellmanPkcs11 over the in-process <c>ManagedSoftToken</c>: two on-token EC key pairs derive
/// the same raw shared secret (CKM_ECDH1_DERIVE + CKD_NULL), cross-checked against the BCL
/// <see cref="ECDiffieHellman"/>. Exercises C_DeriveKey end-to-end without SoftHSM.
/// </summary>
public sealed class ECDiffieHellmanPkcs11Tests_Managed
{
    [Fact]
    public void DeriveRawSecret_BothParties_Match_AndMatchBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var aliceKey = workspace.GenerateEcKeyPair(EcCurve.P256);
        using var bobKey = workspace.GenerateEcKeyPair(EcCurve.P256);
        using var alice = new ECDiffieHellmanPkcs11(aliceKey);
        using var bob = new ECDiffieHellmanPkcs11(bobKey);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);
        Assert.Equal(aliceZ, bobZ);

        // Cross-check the token's ECDH against the BCL: alice-vs-BCL must agree in both directions.
        using var bcl = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.Equal(
            bcl.DeriveRawSecretAgreement(alice.PublicKey),
            alice.DeriveRawSecretAgreement(bcl.PublicKey));
    }
}
