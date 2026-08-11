using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>opencryptoki counterpart of DeriveSharedSecretEcdhTests_SoftHsm (ECDH1 CKD_NULL over P-256).</summary>
[Collection("OpenCryptoki")]
public sealed class DeriveSharedSecretEcdhTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static byte[] ReadEcPoint(Pkcs11Workspace workspace, ObjectHandle publicHandle)
    {
        using var attrs = workspace.Session.GetAttributeValue(publicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }

    [ConditionalFact(nameof(Available))]
    public void TwoParties_DeriveMatchingAesKey()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        byte[] alicePoint = ReadEcPoint(workspace, alice.PublicHandle);
        byte[] bobPoint = ReadEcPoint(workspace, bob.PublicHandle);

        using var aliceAes = workspace.DeriveSharedSecretEcdh(alice, bobPoint, kdf: CKD.CKD_NULL);
        using var bobAes = workspace.DeriveSharedSecretEcdh(bob, alicePoint, kdf: CKD.CKD_NULL);

        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] plaintext = Encoding.UTF8.GetBytes("ECDH-derived AES key must match on both sides");

        byte[] ciphertext = TestAesGcm.Encrypt(workspace.Session, aliceAes.PrivateHandle, iv, plaintext);
        byte[] recovered = TestAesGcm.Decrypt(workspace.Session, bobAes.PrivateHandle, iv, ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [ConditionalFact(nameof(Available))]
    public void RejectsWrongAesBitLength()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] point = ReadEcPoint(workspace, alice.PublicHandle);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => workspace.DeriveSharedSecretEcdh(alice, point, aesBitLength: 100));
    }

    [ConditionalFact(nameof(Available))]
    public void NullKey_Throws()
    {
        using var workspace = OpenWorkspace();
        Assert.Throws<ArgumentNullException>(
            () => workspace.DeriveSharedSecretEcdh(null!, new byte[1]));
    }
}
