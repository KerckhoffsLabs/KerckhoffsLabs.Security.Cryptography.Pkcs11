using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases generate keys for mechanisms outside the default policy on purpose, under a scoped AllowInsecure
// lease; the compile-time policy analyzer flags them, so its warnings are suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// The secret-key generators: one per HMAC hash, Camellia, Poly1305 and Salsa20.
internal static partial class MechanismCoverageTestCases
{
    public static TheoryData<string> KeyGenFamilies => FamiliesWhere(f => f.KeyGen is not null);

    // Generates a session secret key with the mechanism and template given, checks the attributes PKCS#11 v3.2 has
    // the token set (its key type, its length, CKA_LOCAL and, unless the backend's wrapper says it
    // records another, CKA_KEY_GEN_MECHANISM), then hands it to use.
    private static void AssertGenerates(IPkcs11Backend backend, CKM mechanism, CKK keyType, ulong length, CKA[] usages,
        Action<Pkcs11SessionCore, ObjectHandle> use, bool recordsTheKeyGenMechanism = true, bool valueLenReadable = true,
        bool marksTheKeyLocal = true)
    {
        WithSession(backend, session =>
        {
            using var template = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_TOKEN, false), new(CKA.CKA_VALUE_LEN, length),
                .. usages.Select(u => new ObjectAttribute(u, true)),
            ]);
            ObjectHandle key = Taken(() => session.GenerateKey(new Mechanism(mechanism), template.Attributes), $"{mechanism} for a {length}-byte key");
            try
            {
                Assert.Equal((ulong)keyType, ReadULong(session, key, CKA.CKA_KEY_TYPE));
                if (valueLenReadable)
                    Assert.Equal(length, ReadULong(session, key, CKA.CKA_VALUE_LEN));
                if (marksTheKeyLocal)
                {
                    using var local = session.GetAttributeValue(key, [CKA.CKA_LOCAL]);
                    Assert.True(local[0].GetValueAsBool(), $"A key {mechanism} generated is not CKA_LOCAL.");
                }
                if (recordsTheKeyGenMechanism)
                    Assert.Equal((ulong)mechanism, ReadULong(session, key, CKA.CKA_KEY_GEN_MECHANISM));
                use(session, key);
            }
            finally { session.DestroyObject(key); }
        });
    }

    // Each HMAC key generator makes a key of its own key type, which its HMAC signs and verifies with (unless the
    // backend's wrapper says that HMAC does not take it).
    internal static void Assert_HmacKeyGen_MakesAKeyItsHmacTakes(IPkcs11Backend backend, string familyName, bool recordsTheKeyGenMechanism = true,
        bool hmacTakesTheKey = true)
    {
        HashFamily family = Family(familyName);
        CKM keyGen = family.KeyGen!.Value;
        backend.RequireMechanisms(keyGen, family.Hmac!.Value);
        AssertGenerates(backend, keyGen, family.HmacKeyType!.Value, (ulong)family.Size, [CKA.CKA_SIGN, CKA.CKA_VERIFY], (session, key) =>
        {
            if (!hmacTakesTheKey)
                return;
            var hmac = new Mechanism(family.Hmac.Value);
            byte[] mac = session.Sign(hmac, key, Message);
            Assert.Equal(family.Size, mac.Length);
            Assert.True(session.Verify(hmac, key, Message, mac));
            mac[0] ^= 0x01;
            Assert.False(session.Verify(hmac, key, Message, mac));
        }, recordsTheKeyGenMechanism);
    }

    // CKM_SHA512_T_KEY_GEN makes a CKK_SHA512_T_HMAC key (PKCS#11 v3.2).
    internal static void Assert_Sha512TKeyGen_MakesASha512THmacKey(IPkcs11Backend backend, bool recordsTheKeyGenMechanism = true)
    {
        backend.RequireMechanism(CKM.CKM_SHA512_T_KEY_GEN);
        AssertGenerates(backend, CKM.CKM_SHA512_T_KEY_GEN, CKK.CKK_SHA512_T_HMAC, 32, [CKA.CKA_SIGN, CKA.CKA_VERIFY], (_, _) => { }, recordsTheKeyGenMechanism);
    }

    // CKM_CAMELLIA_KEY_GEN makes 128-, 192- and 256-bit Camellia keys, each of which encrypts and decrypts.
    public static TheoryData<int> CamelliaKeyLengths => [16, 24, 32];

    internal static void Assert_CamelliaKeyGen_MakesAKeyCamelliaTakes(IPkcs11Backend backend, int length, bool valueLenReadable = true,
        bool marksTheKeyLocal = true, bool recordsTheKeyGenMechanism = true)
    {
        backend.RequireMechanisms(CKM.CKM_CAMELLIA_KEY_GEN, CKM.CKM_CAMELLIA_CBC_PAD);
        AssertGenerates(backend, CKM.CKM_CAMELLIA_KEY_GEN, CKK.CKK_CAMELLIA, (ulong)length, [CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT], (session, key) =>
        {
            var mechanism = new Mechanism(CKM.CKM_CAMELLIA_CBC_PAD, Iv16);
            byte[] ciphertext = session.Encrypt(mechanism, key, Message);
            Assert.Equal((Message.Length / 16 + 1) * 16, ciphertext.Length);
            Assert.Equal(Message, session.Decrypt(mechanism, key, ciphertext));
        }, recordsTheKeyGenMechanism, valueLenReadable, marksTheKeyLocal);
    }

    // CKM_POLY1305_KEY_GEN makes a 32-byte CKK_POLY1305 key, which CKM_POLY1305 signs and verifies with.
    internal static void Assert_Poly1305KeyGen_MakesAKeyPoly1305Takes(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_POLY1305_KEY_GEN, CKM.CKM_POLY1305);
        AssertGenerates(backend, CKM.CKM_POLY1305_KEY_GEN, CKK.CKK_POLY1305, 32, [CKA.CKA_SIGN, CKA.CKA_VERIFY], (session, key) =>
        {
            var mechanism = new Mechanism(CKM.CKM_POLY1305);
            byte[] tag = session.Sign(mechanism, key, Message);
            Assert.Equal(16, tag.Length);
            Assert.True(session.Verify(mechanism, key, Message, tag));
        });
    }

    // CKM_SALSA20_KEY_GEN makes a 32-byte CKK_SALSA20 key, which CKM_SALSA20 encrypts and decrypts with.
    internal static void Assert_Salsa20KeyGen_MakesAKeySalsa20Takes(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SALSA20_KEY_GEN, CKM.CKM_SALSA20);
        AssertGenerates(backend, CKM.CKM_SALSA20_KEY_GEN, CKK.CKK_SALSA20, 32, [CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT], (session, key) =>
        {
            var mechanism = new Mechanism(CKM.CKM_SALSA20, new CkmSalsa20Params(new byte[8], new byte[8], 64));
            byte[] ciphertext = session.Encrypt(mechanism, key, Message);
            Assert.Equal(Message.Length, ciphertext.Length);
            Assert.Equal(Message, session.Decrypt(mechanism, key, ciphertext));
        });
    }
}
