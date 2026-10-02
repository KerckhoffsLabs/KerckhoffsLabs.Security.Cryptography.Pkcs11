using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class DeriveSharedSecretEcdhTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static byte[] ReadEcPoint(Pkcs11Workspace workspace, ObjectHandle publicHandle)
    {
        using var attrs = workspace.Session.GetAttributeValue(publicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }

    // Two parties run ECDH1 (CKD_NULL) over P-256; the derived on-token AES keys must be identical,
    // proven by a cross-party AES-GCM encrypt-with-Alice / decrypt-with-Bob round-trip.
    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TwoParties_DeriveMatchingAesKey()
    {
        using var workspace = OpenWorkspace();
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL is gated by default — it's what's under test here
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        byte[] alicePoint = ReadEcPoint(workspace, alice.PublicHandle);
        byte[] bobPoint = ReadEcPoint(workspace, bob.PublicHandle);

        // CKD_NULL: the raw shared secret Z (P-256 field size = 32 bytes) becomes the AES-256 key
        // material directly.
        using var aliceAes = workspace.DeriveSharedSecretEcdh(alice, bobPoint, kdf: CKD.CKD_NULL);
        using var bobAes = workspace.DeriveSharedSecretEcdh(bob, alicePoint, kdf: CKD.CKD_NULL);

        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] plaintext = Encoding.UTF8.GetBytes("ECDH-derived AES key must match on both sides");

        byte[] ciphertext = TestAesGcm.Encrypt(workspace.Session, aliceAes.PrivateHandle, iv, plaintext);
        byte[] recovered = TestAesGcm.Decrypt(workspace.Session, bobAes.PrivateHandle, iv, ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RejectsWrongAesBitLength()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] point = ReadEcPoint(workspace, alice.PublicHandle);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => workspace.DeriveSharedSecretEcdh(alice, point, aesBitLength: 100));
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void NullKey_Throws()
    {
        using var workspace = OpenWorkspace();
        Assert.Throws<ArgumentNullException>(
            () => workspace.DeriveSharedSecretEcdh(null!, new byte[1]));
    }

    // === ECParameters overload: validates the peer, then agrees exactly like the raw-span form ===

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TwoParties_DeriveMatchingAesKey_ViaECParametersOverload()
    {
        using var workspace = OpenWorkspace();
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL is gated by default — it's what's under test here
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        using var aliceEcdh = new ECDiffieHellmanPkcs11(alice);
        using var bobEcdh = new ECDiffieHellmanPkcs11(bob);
        ECParameters alicePub = aliceEcdh.ExportParameters(includePrivateParameters: false);
        ECParameters bobPub = bobEcdh.ExportParameters(includePrivateParameters: false);

        using var aliceAes = workspace.DeriveSharedSecretEcdh(alice, bobPub, kdf: CKD.CKD_NULL);
        using var bobAes = workspace.DeriveSharedSecretEcdh(bob, alicePub, kdf: CKD.CKD_NULL);

        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] plaintext = Encoding.UTF8.GetBytes("ECParameters overload must validate and still agree");
        byte[] ciphertext = TestAesGcm.Encrypt(workspace.Session, aliceAes.PrivateHandle, iv, plaintext);
        byte[] recovered = TestAesGcm.Decrypt(workspace.Session, bobAes.PrivateHandle, iv, ciphertext);
        Assert.Equal(plaintext, recovered);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ECParametersOverload_RejectsPeerOnDifferentCurve()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP384);
        using var bobEcdh = new ECDiffieHellmanPkcs11(bob);
        ECParameters bobPub = bobEcdh.ExportParameters(includePrivateParameters: false);

        Assert.Throws<ArgumentException>(() => workspace.DeriveSharedSecretEcdh(alice, bobPub));
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_TwoParties_ReadBackTheSameSecret()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "Kryoptic", "PKCS11_TEST_EXPECT_KRYOPTIC");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_TwoParties_ReadBackTheSameSecret(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_KnownAnswer()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "Kryoptic", "PKCS11_TEST_EXPECT_KRYOPTIC");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_X25519KnownAnswer(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X448_KnownAnswer()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "Kryoptic", "PKCS11_TEST_EXPECT_KRYOPTIC");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_X448KnownAnswer(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_LowOrderPeer_IsRefused()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "Kryoptic", "PKCS11_TEST_EXPECT_KRYOPTIC");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_LowOrderPeer_IsRefused(workspace);
    }
}
