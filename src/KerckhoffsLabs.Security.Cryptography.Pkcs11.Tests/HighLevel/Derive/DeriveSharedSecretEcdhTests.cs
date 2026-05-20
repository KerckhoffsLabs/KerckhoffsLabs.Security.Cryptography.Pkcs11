using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
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
                var aliceAttrs = session.GetAttributeValue(alicePub, [CKA.CKA_EC_POINT]);
                var bobAttrs = session.GetAttributeValue(bobPub, [CKA.CKA_EC_POINT]);
                byte[] alicePoint;
                byte[] bobPoint;
                try
                {
                    alicePoint = aliceAttrs[0].GetValueAsByteArray();
                    bobPoint = bobAttrs[0].GetValueAsByteArray();
                }
                finally
                {
                    foreach (var a in aliceAttrs) a.Dispose();
                    foreach (var a in bobAttrs) a.Dispose();
                }

                // Both parties derive AES-256 keys from the shared secret.
                ObjectHandle aliceKey = session.DeriveSharedSecretEcdh(alicePriv, bobPoint);
                ObjectHandle bobKey = session.DeriveSharedSecretEcdh(bobPriv, alicePoint);
                try
                {
                    // Encrypt the same plaintext with both derived keys and check the ciphertext+tag matches.
                    // All-zero IV is intentional and safe here: this is a test-only proof of key agreement,
                    // not production code. Both encryptions use DIFFERENT keys (aliceKey, bobKey) so there
                    // is no nonce reuse on a single key. The fixed IV is required to make the output
                    // deterministic so the byte-equality check is meaningful. Never use a fixed IV in production.
                    byte[] iv = new byte[12];
                    byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("phase-4a ECDH sanity check");
                    byte[] ctA = session.EncryptAesGcm(aliceKey, iv, plaintext);
                    byte[] ctB = session.EncryptAesGcm(bobKey, iv, plaintext);
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
    public static bool SoftHsmSupportsEcdh1WithKdf => SoftHsmBackendFixture.SoftHsmSupportsEcdh1WithKdf;

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsEcdh1WithKdf))]
    public void Ecdh_BothPartiesDeriveSameSecret() => DeriveSharedSecretEcdhTestCases.Assert_Ecdh_BothPartiesDeriveSameSecret(_backend);
}
