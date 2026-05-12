using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Derive;

internal static class DeriveSharedSecretEcdhTestCases
{
    internal static void Assert_Ecdh_BothPartiesDeriveSameSecret(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            // Alice and Bob each generate a P-256 key pair.
            var (alicePub, alicePriv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
            var (bobPub, bobPriv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
            try
            {
                // Extract each peer's public point (CKA_EC_POINT is a DER-encoded OCTET STRING).
                var aliceAttrs = session.GetAttributeValue(alicePub, new List<CKA> { CKA.CKA_EC_POINT });
                var bobAttrs   = session.GetAttributeValue(bobPub,   new List<CKA> { CKA.CKA_EC_POINT });
                byte[] alicePoint;
                byte[] bobPoint;
                try
                {
                    alicePoint = aliceAttrs[0].GetValueAsByteArray();
                    bobPoint   = bobAttrs[0].GetValueAsByteArray();
                }
                finally
                {
                    foreach (var a in aliceAttrs) a.Dispose();
                    foreach (var a in bobAttrs) a.Dispose();
                }

                // Both parties derive AES-256 keys from the shared secret.
                ObjectHandle aliceKey = session.DeriveSharedSecretEcdh(alicePriv, bobPoint);
                ObjectHandle bobKey   = session.DeriveSharedSecretEcdh(bobPriv,   alicePoint);
                try
                {
                    // Encrypt the same plaintext with both derived keys and check the ciphertext+tag matches.
                    // Use AES-GCM with a fixed IV so the encryption is deterministic per key.
                    byte[] iv = new byte[12];
                    byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("phase-4a ECDH sanity check");
                    byte[] ctA = session.EncryptAesGcm(aliceKey, iv, plaintext);
                    byte[] ctB = session.EncryptAesGcm(bobKey,   iv, plaintext);
                    Assert.Equal(ctA, ctB);
                }
                finally
                {
                    session.DestroyObject(bobKey);
                    session.DestroyObject(aliceKey);
                }
            }
            finally
            {
                session.DestroyObject(alicePriv);
                session.DestroyObject(alicePub);
                session.DestroyObject(bobPriv);
                session.DestroyObject(bobPub);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class DeriveSharedSecretEcdhTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ecdh_BothPartiesDeriveSameSecret() => DeriveSharedSecretEcdhTestCases.Assert_Ecdh_BothPartiesDeriveSameSecret(_backend);
}
