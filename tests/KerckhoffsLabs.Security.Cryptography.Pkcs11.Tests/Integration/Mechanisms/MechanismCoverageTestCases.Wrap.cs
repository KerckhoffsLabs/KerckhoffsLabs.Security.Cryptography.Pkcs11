using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases wrap under mechanisms outside the default policy (ECB, the feedback modes, Camellia, PKCS#1 v1.5) on
// purpose, under a scoped AllowInsecure lease; the compile-time policy analyzer flags them, so its warnings are
// suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// Key wrapping under each cipher that wraps, and RSA PKCS#1 v1.5 key encapsulation.
internal static partial class MechanismCoverageTestCases
{
    private static readonly byte[] WrappedSecret = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x70 + i))];

    // The mechanisms that wrap a secret key's value as they encrypt it (PKCS#11 v3.2, C_WrapKey): ECB, CBC and CBC_PAD
    // under AES and Camellia, AES's feedback modes and GCM. Each wraps a 32-byte secret, which needs no padding.
    public static TheoryData<string> WrapMechanisms =>
        ["AES-ECB", "AES-CBC", "AES-CBC-PAD", "AES-OFB", "AES-CFB8", "AES-CFB64", "AES-CFB128", "AES-GCM",
         "Camellia-ECB", "Camellia-CBC", "Camellia-CBC-PAD"];

    private static (CKM Type, Func<Mechanism> Mechanism, CKK KeyType, byte[] Key) WrapMechanism(string name) => name switch
    {
        "AES-ECB" => (CKM.CKM_AES_ECB, () => new Mechanism(CKM.CKM_AES_ECB), CKK.CKK_AES, AesKey),
        "AES-CBC" => (CKM.CKM_AES_CBC, () => new Mechanism(CKM.CKM_AES_CBC, Iv16), CKK.CKK_AES, AesKey),
        "AES-CBC-PAD" => (CKM.CKM_AES_CBC_PAD, () => new Mechanism(CKM.CKM_AES_CBC_PAD, Iv16), CKK.CKK_AES, AesKey),
        "AES-OFB" => (CKM.CKM_AES_OFB, () => new Mechanism(CKM.CKM_AES_OFB, Iv16), CKK.CKK_AES, AesKey),
        "AES-CFB8" => (CKM.CKM_AES_CFB8, () => new Mechanism(CKM.CKM_AES_CFB8, Iv16), CKK.CKK_AES, AesKey),
        "AES-CFB64" => (CKM.CKM_AES_CFB64, () => new Mechanism(CKM.CKM_AES_CFB64, Iv16), CKK.CKK_AES, AesKey),
        "AES-CFB128" => (CKM.CKM_AES_CFB128, () => new Mechanism(CKM.CKM_AES_CFB128, Iv16), CKK.CKK_AES, AesKey),
        "AES-GCM" => (CKM.CKM_AES_GCM, () => new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(Iv16[..12], "aad"u8, 128)), CKK.CKK_AES, AesKey),
        "Camellia-ECB" => (CKM.CKM_CAMELLIA_ECB, () => new Mechanism(CKM.CKM_CAMELLIA_ECB), CKK.CKK_CAMELLIA, CamelliaKey),
        "Camellia-CBC" => (CKM.CKM_CAMELLIA_CBC, () => new Mechanism(CKM.CKM_CAMELLIA_CBC, Iv16), CKK.CKK_CAMELLIA, CamelliaKey),
        "Camellia-CBC-PAD" => (CKM.CKM_CAMELLIA_CBC_PAD, () => new Mechanism(CKM.CKM_CAMELLIA_CBC_PAD, Iv16), CKK.CKK_CAMELLIA, CamelliaKey),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    // C_WrapKey of a generic secret gives what C_Encrypt gives for its value under the same mechanism and parameter,
    // and C_UnwrapKey of that gives back a key with the same value (compared through an HMAC under it).
    // Where the backend's wrapper says the token's C_Encrypt reports a longer output than it wrote (a length-keeping
    // mode only), the case compares the key's length of it.
    internal static void Assert_Wrap_IsTheEncryptionOfTheKeyValue(IPkcs11Backend backend, string name, bool encryptReportsTheOutputLength = true)
    {
        (CKM type, Func<Mechanism> mechanism, CKK keyType, byte[] key) = WrapMechanism(name);
        backend.RequireMechanismFlags(type, f => f.Wrap && f.Unwrap && f.Encrypt, "C_WrapKey, C_UnwrapKey and C_Encrypt");
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithSession(backend, session =>
        {
            ObjectHandle kek = CreateSecret(session, keyType, key, CKA.CKA_WRAP, CKA.CKA_UNWRAP, CKA.CKA_ENCRYPT);
            ObjectHandle target;
            using (var targetTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_VALUE, WrappedSecret), new(CKA.CKA_EXTRACTABLE, true), new(CKA.CKA_SENSITIVE, false),
            ]))
                target = session.CreateObject(targetTemplate.Attributes);
            ObjectHandle? unwrapped = null;
            try
            {
                byte[] wrapped = Taken(() => session.WrapKey(mechanism(), kek, target), $"C_WrapKey under {type}");
                byte[] encrypted = session.Encrypt(mechanism(), kek, WrappedSecret);
                if (!encryptReportsTheOutputLength)
                    encrypted = encrypted[..WrappedSecret.Length];
                Assert.Equal(Convert.ToHexStringLower(encrypted), Convert.ToHexStringLower(wrapped));
                unwrapped = UnwrapGenericSecret(session, mechanism(), kek, wrapped);
                Assert.Equal(HMACSHA256.HashData(WrappedSecret, Message), HmacUnder(session, unwrapped.Value));
            }
            finally
            {
                if (unwrapped is { } u)
                    session.DestroyObject(u);
                session.DestroyObject(target);
                session.DestroyObject(kek);
            }
        });
    }

    // Unwraps a generic secret that can sign. PKCS#11 v3.2 reads two ways here: the common footnotes to the attribute
    // tables say CKA_VALUE_LEN must not be given to C_UnwrapKey (SoftHSM refuses it as CKR_ATTRIBUTE_READ_ONLY), while
    // the block cipher modes truncate an unwrapped value "according to … the CKA_VALUE_LEN attribute of the template,
    // if it has one" (BouncyHsm asks for it, with CKR_TEMPLATE_INCONSISTENT where a missing attribute is
    // CKR_TEMPLATE_INCOMPLETE). The case tries the first, then the second.
    private static ObjectHandle UnwrapGenericSecret(Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle kek, byte[] wrapped)
    {
        using var template = new Template(
        [
            new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET), new(CKA.CKA_TOKEN, false),
            new(CKA.CKA_SIGN, true),
        ]);
        try { return session.UnwrapKey(mechanism, kek, wrapped, template.Attributes); }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_TEMPLATE_INCOMPLETE or CKR.CKR_TEMPLATE_INCONSISTENT)
        {
            using var withLength = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_SIGN, true), new(CKA.CKA_VALUE_LEN, (ulong)WrappedSecret.Length),
            ]);
            return session.UnwrapKey(mechanism, kek, wrapped, withLength.Attributes);
        }
    }

    // === RSA PKCS#1 v1.5 key encapsulation ======================================

    // Decapsulates a 32-byte generic secret that can sign. As with C_UnwrapKey, tokens read CKA_VALUE_LEN two ways
    // here (opencryptoki decapsulates through its unwrap path and refuses it with CKR_TEMPLATE_INCONSISTENT), so the
    // case gives the length, then leaves it out.
    private static ObjectHandle DecapsulateGenericSecret(Pkcs11SessionCore session, ObjectHandle priv, byte[] ciphertext)
    {
        using var withLength = MacSecretTemplate(32);
        try { return session.DecapsulateKey(new Mechanism(CKM.CKM_RSA_PKCS), priv, ciphertext, withLength.Attributes); }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_TEMPLATE_INCONSISTENT or CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            using var withoutLength = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_SIGN, true),
            ]);
            return session.DecapsulateKey(new Mechanism(CKM.CKM_RSA_PKCS), priv, ciphertext, withoutLength.Attributes);
        }
    }

    // C_EncapsulateKey with CKM_RSA_PKCS (PKCS#11 v3.2) makes a secret and returns it encrypted under
    // the public key as PKCS#1 v1.5 does; the runtime decrypts it to the secret the token kept, and
    // C_DecapsulateKey gives the token the same secret back.
    internal static void Assert_RsaPkcs_EncapsulatesAPkcs1EncryptedSecret(IPkcs11Backend backend)
    {
        // MechanismFlags has no Encapsulate/Decapsulate property yet, so the case reads the CKF bits.
        backend.RequireMechanismFlags(CKM.CKM_RSA_PKCS, f => (f.Flags & (CKF.CKF_ENCAPSULATE | CKF.CKF_DECAPSULATE)) == (CKF.CKF_ENCAPSULATE | CKF.CKF_DECAPSULATE),
            "C_EncapsulateKey and C_DecapsulateKey");
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        RSAParameters k = SigningRsa.Value.ExportParameters(true);
        WithSession(backend, session =>
        {
            using var publicTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_RSA), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_ENCAPSULATE, true), new(CKA.CKA_MODULUS, k.Modulus!), new(CKA.CKA_PUBLIC_EXPONENT, k.Exponent!),
            ]);
            using var privateTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_RSA), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_DECAPSULATE, true), new(CKA.CKA_MODULUS, k.Modulus!), new(CKA.CKA_PUBLIC_EXPONENT, k.Exponent!),
                new(CKA.CKA_PRIVATE_EXPONENT, k.D!), new(CKA.CKA_PRIME_1, k.P!), new(CKA.CKA_PRIME_2, k.Q!),
                new(CKA.CKA_EXPONENT_1, k.DP!), new(CKA.CKA_EXPONENT_2, k.DQ!), new(CKA.CKA_COEFFICIENT, k.InverseQ!),
            ]);
            ObjectHandle pub = session.CreateObject(publicTemplate.Attributes);
            ObjectHandle priv = session.CreateObject(privateTemplate.Attributes);
            ObjectHandle? encapsulated = null, decapsulated = null;
            try
            {
                using var secretTemplate = MacSecretTemplate(32);
                (byte[] ciphertext, ObjectHandle shared) = Taken(
                    () => session.EncapsulateKey(new Mechanism(CKM.CKM_RSA_PKCS), pub, secretTemplate.Attributes), "C_EncapsulateKey with CKM_RSA_PKCS");
                encapsulated = shared;
                Assert.Equal(256, ciphertext.Length);
                byte[] secret = SigningRsa.Value.Decrypt(ciphertext, RSAEncryptionPadding.Pkcs1);
                Assert.Equal(32, secret.Length);
                Assert.Equal(HMACSHA256.HashData(secret, Message), HmacUnder(session, shared));

                decapsulated = DecapsulateGenericSecret(session, priv, ciphertext);
                Assert.Equal(HMACSHA256.HashData(secret, Message), HmacUnder(session, decapsulated.Value));
            }
            finally
            {
                if (decapsulated is { } d)
                    session.DestroyObject(d);
                if (encapsulated is { } e)
                    session.DestroyObject(e);
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }
}
