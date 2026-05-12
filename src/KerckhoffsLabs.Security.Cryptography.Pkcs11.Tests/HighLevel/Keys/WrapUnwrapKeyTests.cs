using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class WrapUnwrapKeyTestCases
{
    internal static void Assert_AesKeyWrapPad_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            // KEK can stay non-extractable — it's the wrapping key, not wrapped.
            ObjectHandle kek = session.GenerateAesKey(bitLength: 256);

            // Data key MUST be extractable to be wrappable. The secure-default
            // helper sets CKA_EXTRACTABLE=false, so build the template manually here.
            using var dkClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var dkKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var dkValueLen  = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var dkToken     = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var dkSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var dkExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var dkEncrypt   = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var dkDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);
            var dkTemplate = new List<ObjectAttribute> { dkClass, dkKeyType, dkValueLen, dkToken, dkSensitive, dkExtract, dkEncrypt, dkDecrypt };
            using var keyGenMech = new Mechanism(CKM.CKM_AES_KEY_GEN);
            ObjectHandle dataKey = session.GenerateKey(keyGenMech, dkTemplate);

            try
            {
                // Encrypt a known plaintext with the original data key.
                byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("phase-4a wrap round-trip plaintext");
                byte[] ciphertext = session.EncryptAesGcm(dataKey, iv, plaintext);

                using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);
                Assert.NotEmpty(wrapped);

                // Unwrap into a fresh handle — extractable+encrypt+decrypt so we can
                // verify the key material survived by decrypting the ciphertext.
                using var attrClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var attrKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var attrToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var attrEncrypt  = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var attrDecrypt  = new ObjectAttribute(CKA.CKA_DECRYPT, true);
                var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt };

                ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    // The real assertion: the unwrapped key must produce the original
                    // plaintext when decrypting the ciphertext from the original key.
                    byte[] recovered = session.DecryptAesGcm(unwrapped, iv, ciphertext);
                    Assert.Equal(plaintext, recovered);
                }
                finally
                {
                    session.DestroyObject(unwrapped);
                }
            }
            finally
            {
                session.DestroyObject(dataKey);
                session.DestroyObject(kek);
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
public sealed class WrapUnwrapKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);
}
