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

    // The round-trip verifies the derived key with classic-params AES-GCM, which NSS rejects; the
    // derive itself works, but the verification path does not, so this case skips (see NssBackendFixture).

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    private static byte[] ReadEcPoint(Pkcs11Workspace workspace, ObjectHandle publicHandle)
    {
        using var attrs = workspace.Session.GetAttributeValue(publicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    public void TwoParties_DeriveMatchingAesKey()
    {
        using var workspace = OpenWorkspace();
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL is gated by default — it's what's under test here
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

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RejectsWrongAesBitLength()
    {
        using var workspace = OpenWorkspace();
        using var alice = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] point = ReadEcPoint(workspace, alice.PublicHandle);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => workspace.DeriveSharedSecretEcdh(alice, point, aesBitLength: 100));
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void NullKey_Throws()
    {
        using var workspace = OpenWorkspace();
        Assert.Throws<ArgumentNullException>(
            () => workspace.DeriveSharedSecretEcdh(null!, new byte[1]));
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_TwoParties_ReadBackTheSameSecret()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "NSS", "PKCS11_TEST_EXPECT_NSS");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_TwoParties_ReadBackTheSameSecret(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_KnownAnswer()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "NSS", "PKCS11_TEST_EXPECT_NSS");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_X25519KnownAnswer(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X448_KnownAnswer()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "NSS", "PKCS11_TEST_EXPECT_NSS");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_X448KnownAnswer(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_LowOrderPeer_IsRefused()
    {
        X25519ReadBackTestCases.RequireX25519(_backend.Supports(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN) && _backend.Supports(CKM.CKM_ECDH1_DERIVE), "NSS", "PKCS11_TEST_EXPECT_NSS");
        using var workspace = OpenWorkspace();
        X25519ReadBackTestCases.Assert_LowOrderPeer_IsRefused(workspace);
    }
}
