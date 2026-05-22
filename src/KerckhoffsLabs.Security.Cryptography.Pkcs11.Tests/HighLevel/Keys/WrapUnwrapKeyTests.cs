using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

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
            using var dkClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var dkKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var dkValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var dkToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var dkSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var dkExtract = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var dkEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var dkDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
            var dkTemplate = new List<ObjectAttribute> { dkClass, dkKeyType, dkValueLen, dkToken, dkSensitive, dkExtract, dkEncrypt, dkDecrypt };
            using var keyGenMech = new Mechanism(CKM.CKM_AES_KEY_GEN);
            ObjectHandle dataKey = session.GenerateKey(keyGenMech, dkTemplate);

            try
            {
                // Encrypt a known plaintext with the original data key.
                byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("phase-4a wrap round-trip plaintext");
                byte[] ciphertext = session.EncryptAesGcm(dataKey, iv, plaintext);

                using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);
                Assert.NotEmpty(wrapped);

                // Unwrap into a fresh handle — extractable+encrypt+decrypt so we can
                // verify the key material survived by decrypting the ciphertext.
                using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
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

    // Sets up a logged-in session with a 256-bit KEK and an extractable AES data key wrapped under
    // it, runs <paramref name="body"/> with (session, kek, wrappedBytes), then tears everything down.
    private static void WithWrappedAesKey(IPkcs11Backend backend, Action<Pkcs11Session, ObjectHandle, byte[]> body)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle kek = session.GenerateAesKey(bitLength: 256);
            using var dkClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var dkKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var dkValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var dkToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var dkSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var dkExtract = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            var dkTemplate = new List<ObjectAttribute> { dkClass, dkKeyType, dkValueLen, dkToken, dkSensitive, dkExtract };
            using var keyGenMech = new Mechanism(CKM.CKM_AES_KEY_GEN);
            ObjectHandle dataKey = session.GenerateKey(keyGenMech, dkTemplate);
            try
            {
                using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);
                body(session, kek, wrapped);
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

    /// <summary>BL-017: unwrapping without CKA_SENSITIVE / CKA_EXTRACTABLE must yield a sensitive,
    /// non-extractable key.</summary>
    internal static void Assert_Unwrap_AppliesSecureDefaults(IPkcs11Backend backend)
    {
        WithWrappedAesKey(backend, (session, kek, wrapped) =>
        {
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            // Deliberately omit CKA_SENSITIVE / CKA_EXTRACTABLE — the library must supply them.
            var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken };
            using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);

            ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
            try
            {
                var read = session.GetAttributeValue(unwrapped, [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE]);
                try
                {
                    Assert.True(read.First(a => a.Type == (ulong)CKA.CKA_SENSITIVE).GetValueAsBool(),
                        "unwrapped key should default to CKA_SENSITIVE=true");
                    Assert.False(read.First(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE).GetValueAsBool(),
                        "unwrapped key should default to CKA_EXTRACTABLE=false");
                }
                finally { foreach (var a in read) a.Dispose(); }
            }
            finally { session.DestroyObject(unwrapped); }
        });
    }

    /// <summary>BL-017: an explicit CKA_EXTRACTABLE=true is rejected by default and permitted under
    /// AllowInsecureScope (the resulting key really is extractable).</summary>
    internal static void Assert_Unwrap_ExplicitExtractable_RequiresAllowInsecure(IPkcs11Backend backend)
    {
        WithWrappedAesKey(backend, (session, kek, wrapped) =>
        {
            using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);

            using (var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY))
            using (var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES))
            using (var t = new ObjectAttribute(CKA.CKA_TOKEN, false))
            using (var ex = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true))
            {
                var template = new List<ObjectAttribute> { c, k, t, ex };
                Assert.Throws<InsecureOperationException>(() => session.UnwrapKey(wrapMech, kek, wrapped, template));
            }

            using (var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY))
            using (var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES))
            using (var t = new ObjectAttribute(CKA.CKA_TOKEN, false))
            using (var ex = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true))
            {
                var template = new List<ObjectAttribute> { c, k, t, ex };
                ObjectHandle unwrapped;
                using (session.AllowInsecureScope())
                    unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    var read = session.GetAttributeValue(unwrapped, [CKA.CKA_EXTRACTABLE]);
                    try { Assert.True(read.First(a => a.Type == (ulong)CKA.CKA_EXTRACTABLE).GetValueAsBool()); }
                    finally { foreach (var a in read) a.Dispose(); }
                }
                finally { session.DestroyObject(unwrapped); }
            }
        });
    }
}

[Collection("SoftHsm")]
public sealed class WrapUnwrapKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Unwrap_AppliesSecureDefaults() => WrapUnwrapKeyTestCases.Assert_Unwrap_AppliesSecureDefaults(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Unwrap_ExplicitExtractable_RequiresAllowInsecure() => WrapUnwrapKeyTestCases.Assert_Unwrap_ExplicitExtractable_RequiresAllowInsecure(_backend);
}
