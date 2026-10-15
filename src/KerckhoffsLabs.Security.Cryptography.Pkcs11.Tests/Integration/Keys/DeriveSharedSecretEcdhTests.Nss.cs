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

    // The round-trip verifies the derived key with classic-params AES-GCM, which only NSS 3.52 and later
    // accept (see NssBackendFixture.RequireClassicAesGcm).

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithoutLogin(_backend.TokenLabel);

    private static byte[] ReadEcPoint(Pkcs11Session session, ObjectHandle publicHandle)
    {
        using var attrs = session.Core.GetAttributeValue(publicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    public void TwoParties_DeriveMatchingAesKey()
    {
        _backend.RequireClassicAesGcm();
        using var session = OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL is gated by default — it's what's under test here
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        byte[] alicePoint = ReadEcPoint(session, alice.PublicHandle);
        byte[] bobPoint = ReadEcPoint(session, bob.PublicHandle);

        using var aliceAes = session.DeriveSharedSecretEcdh(alice, bobPoint, kdf: CKD.CKD_NULL);
        using var bobAes = session.DeriveSharedSecretEcdh(bob, alicePoint, kdf: CKD.CKD_NULL);

        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] plaintext = Encoding.UTF8.GetBytes("ECDH-derived AES key must match on both sides");

        byte[] ciphertext = TestAesGcm.Encrypt(session.Core, aliceAes.PrivateHandle, iv, plaintext);
        byte[] recovered = TestAesGcm.Decrypt(session.Core, bobAes.PrivateHandle, iv, ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RejectsWrongAesBitLength()
    {
        using var session = OpenSession();
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] point = ReadEcPoint(session, alice.PublicHandle);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => session.DeriveSharedSecretEcdh(alice, point, aesBitLength: 100));
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void NullKey_Throws()
    {
        using var session = OpenSession();
        Assert.Throws<ArgumentNullException>(
            () => session.DeriveSharedSecretEcdh(null!, new byte[1]));
    }
}
