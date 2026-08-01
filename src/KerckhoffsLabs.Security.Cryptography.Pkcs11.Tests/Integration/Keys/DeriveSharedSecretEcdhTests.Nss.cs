using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of DeriveSharedSecretEcdhTests_SoftHsm (ECDH1 CKD_NULL over P-256).</summary>
[Collection("Nss")]
public sealed class DeriveSharedSecretEcdhTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // The round-trip verifies the derived key with classic-params AES-GCM, which NSS rejects; the
    // derive itself works, but the verification path does not, so this case skips (see NssBackendFixture).
    public static bool ClassicGcm => NssBackendFixture.ClassicAesGcmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    private static byte[] ReadEcPoint(Pkcs11Workspace workspace, ObjectHandle publicHandle)
    {
        using var attrs = workspace.Session.GetAttributeValue(publicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }

    [ConditionalFact(nameof(ClassicGcm))]
    public void TwoParties_DeriveMatchingAesKey()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP256);
        using var bob = workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP256);

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
        using var alice = workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP256);
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
