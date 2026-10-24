using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// CKM_AES_CBC_PAD is unauthenticated and gated by default. It is used here because it is how NSS
// wraps private keys itself, and because .NET can encrypt and decrypt it, so a test can both build a
// foreign PKCS#8 and read back what the token wrapped. The warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic tests for wrapping and unwrapping Ed25519 (<see cref="CKK.CKK_EC_EDWARDS"/>) and
/// X25519 (<see cref="CKK.CKK_EC_MONTGOMERY"/>) private keys. A wrapped private key is a PKCS#8
/// <c>OneAsymmetricKey</c> (RFC 5958), and RFC 8410 fixes its form for these curves: the curve's
/// AlgorithmIdentifier with no parameters, and the key as a <c>CurvePrivateKey</c> OCTET STRING inside
/// the <c>privateKey</c> OCTET STRING. Version 0 carries nothing else; version 1 may add the public key
/// (BouncyHsm writes it). A token that encodes the key any other way cannot exchange keys with OpenSSL
/// or another token, which is what these cases check.
/// </summary>
/// <remarks>
/// <para>
/// Every case wraps under an AES key whose value the test holds, so it can decrypt what the token
/// wrapped and read the PKCS#8 back. The known-answer cases unwrap the RFC test keys, encoded and
/// encrypted here as a key exported by OpenSSL arrives; the round-trip cases start from a
/// token-generated key.
/// </para>
/// <para>
/// Each known-answer case also uses the key it unwrapped: the Ed25519 one signs RFC 8032's message
/// to RFC 8032's signature, and the X25519 one agrees RFC 7748's secret. The X25519 round trip agrees
/// a secret with the original and with the copy and compares the two; the Ed25519 one signs with both.
/// </para>
/// <para>
/// A case skips unless the token advertises the curve's key-pair generation mechanism, which stands in
/// for supporting the key type at all (SoftHSM has no <see cref="CKK.CKK_EC_MONTGOMERY"/>).
/// </para>
/// </remarks>
internal static class WrapUnwrapCurve25519TestCases
{
    // Last byte of each curve's OID (1.3.101.x) and its DER, as CKA_EC_PARAMS.
    private const byte Ed25519Oid = 0x70;
    private const byte X25519Oid = 0x6E;
    private static readonly byte[] Ed25519Params = [0x06, 0x03, 0x2B, 0x65, Ed25519Oid];
    private static readonly byte[] X25519Params = [0x06, 0x03, 0x2B, 0x65, X25519Oid];

    // RFC 8032 §7.1, TEST 2: the secret key, a one-byte message, and its signature.
    private static readonly byte[] Rfc8032Test2Secret =
        Convert.FromHexString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    private static readonly byte[] Rfc8032Test2Public =
        Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    private static readonly byte[] Rfc8032Test2Message = [0x72];
    private static readonly byte[] Rfc8032Test2Signature = Convert.FromHexString(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    // RFC 7748 §6.1: Alice's private key, Bob's public key, and the secret they share.
    private static readonly byte[] Rfc7748AlicePrivate =
        Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static readonly byte[] Rfc7748AlicePublic =
        Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static readonly byte[] Rfc7748BobPublic =
        Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static readonly byte[] Rfc7748SharedSecret =
        Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    private static readonly byte[] Message = "wrapped Curve25519 key"u8.ToArray();

    internal static void Assert_Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature(IPkcs11Backend backend)
    {
        RequireEd25519(backend);
        RunInSession(backend, session =>
        {
            using var kek = new Kek(session);
            byte[] pkcs8 = Pkcs8(Ed25519Oid, Rfc8032Test2Secret);

            ObjectHandle key = kek.Unwrap(pkcs8, CKK.CKK_EC_EDWARDS, CKA.CKA_SIGN);

            AssertUsage(session, key, CKK.CKK_EC_EDWARDS, sign: true, derive: false);
            AssertWrapsTheKey(kek.Wrap(key), Ed25519Oid, Rfc8032Test2Secret, Rfc8032Test2Public);
            Assert.Equal(Rfc8032Test2Signature, session.Sign(new Mechanism(CKM.CKM_EDDSA), key, Rfc8032Test2Message));
        });
    }

    // The RFC 8032 key as an RFC 5958 OneAsymmetricKey v2 laid out as RFC 8410 §10.3's second example:
    // version 1, a [0] friendlyName attribute and the [1] public key. Both fields are optional, and a token
    // must take them on unwrap (Kryoptic refused both with CKR_WRAPPED_KEY_INVALID until 1.5.4,
    // latchset/kryoptic#532).
    internal static void Assert_Unwrap_Rfc5958Ed25519KeyWithOptionalFields_SignsTheRfc8032Signature(IPkcs11Backend backend)
    {
        RequireEd25519(backend);
        RunInSession(backend, session =>
        {
            using var kek = new Kek(session);
            byte[] pkcs8 = OneAsymmetricKeyV2(Ed25519Oid, Rfc8032Test2Secret, Rfc8032Test2Public);

            ObjectHandle key = kek.Unwrap(pkcs8, CKK.CKK_EC_EDWARDS, CKA.CKA_SIGN);

            AssertUsage(session, key, CKK.CKK_EC_EDWARDS, sign: true, derive: false);
            AssertWrapsTheKey(kek.Wrap(key), Ed25519Oid, Rfc8032Test2Secret, Rfc8032Test2Public);
            Assert.Equal(Rfc8032Test2Signature, session.Sign(new Mechanism(CKM.CKM_EDDSA), key, Rfc8032Test2Message));
        });
    }

    internal static void Assert_Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret(IPkcs11Backend backend)
    {
        RequireX25519(backend);
        RunInSession(backend, session =>
        {
            using var kek = new Kek(session);
            byte[] pkcs8 = Pkcs8(X25519Oid, Rfc7748AlicePrivate);

            ObjectHandle key = kek.Unwrap(pkcs8, CKK.CKK_EC_MONTGOMERY, CKA.CKA_DERIVE);

            AssertUsage(session, key, CKK.CKK_EC_MONTGOMERY, sign: false, derive: true);
            AssertWrapsTheKey(kek.Wrap(key), X25519Oid, Rfc7748AlicePrivate, Rfc7748AlicePublic);
            // NSS derives only non-extractable keys, so the secret is compared through an HMAC under it.
            Assert.Equal(HMACSHA256.HashData(Rfc7748SharedSecret, Message),
                         HmacUnderSharedSecret(session, key, Rfc7748BobPublic));
        });
    }

    internal static void Assert_WrapUnwrap_Ed25519PrivateKey_KeepsTheKey(IPkcs11Backend backend)
    {
        RequireEd25519(backend);
        RunInSession(backend, session =>
        {
            using var kek = new Kek(session);
            ObjectHandle original = GenerateWrappablePrivateKey(session, CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK.CKK_EC_EDWARDS, Ed25519Params, CKA.CKA_SIGN);

            byte[] pkcs8 = kek.Wrap(original);
            var (privateKey, publicKey) = ReadCurvePrivateKey(pkcs8, Ed25519Oid);
            ObjectHandle copy = kek.Unwrap(pkcs8, CKK.CKK_EC_EDWARDS, CKA.CKA_SIGN);

            AssertUsage(session, copy, CKK.CKK_EC_EDWARDS, sign: true, derive: false);
            AssertWrapsTheKey(kek.Wrap(copy), Ed25519Oid, privateKey, publicKey);
            // Ed25519 is deterministic, so the same key signs a message to the same signature.
            var eddsa = new Mechanism(CKM.CKM_EDDSA);
            Assert.Equal(session.Sign(eddsa, original, Message), session.Sign(eddsa, copy, Message));
        });
    }

    internal static void Assert_WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal(IPkcs11Backend backend)
    {
        RequireX25519(backend);
        RunInSession(backend, session =>
        {
            using var kek = new Kek(session);
            ObjectHandle original = GenerateWrappablePrivateKey(session, CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKK.CKK_EC_MONTGOMERY, X25519Params, CKA.CKA_DERIVE);

            byte[] pkcs8 = kek.Wrap(original);
            var (privateKey, publicKey) = ReadCurvePrivateKey(pkcs8, X25519Oid);
            ObjectHandle copy = kek.Unwrap(pkcs8, CKK.CKK_EC_MONTGOMERY, CKA.CKA_DERIVE);

            AssertUsage(session, copy, CKK.CKK_EC_MONTGOMERY, sign: false, derive: true);
            AssertWrapsTheKey(kek.Wrap(copy), X25519Oid, privateKey, publicKey);
            Assert.Equal(HmacUnderSharedSecret(session, original, Rfc7748BobPublic),
                         HmacUnderSharedSecret(session, copy, Rfc7748BobPublic));
        });
    }

    private static void RequireEd25519(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM.CKM_EDDSA);
        RequireCbcPadKeyWrap(backend);
    }

    private static void RequireX25519(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE, CKM.CKM_SHA256_HMAC);
        RequireCbcPadKeyWrap(backend);
    }

    // Craton HSM lists CKM_AES_CBC_PAD for C_Encrypt and C_Decrypt only, and refuses C_WrapKey and
    // C_UnwrapKey with it (CKR_MECHANISM_INVALID).
    private static void RequireCbcPadKeyWrap(IPkcs11Backend backend) =>
        backend.RequireMechanismFlags(CKM.CKM_AES_CBC_PAD, f => f.Wrap && f.Unwrap, "CKF_WRAP and CKF_UNWRAP");

    // The session runs under AllowInsecure: CBC wrapping, extractable private keys and a raw CKD_NULL
    // agreement are what is under test, and SecureOnly refuses all three.
    private static void RunInSession(IPkcs11Backend backend, Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                body(session);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // RFC 8410 §7 OneAsymmetricKey v1: version 0, the curve's AlgorithmIdentifier with no parameters,
    // and the 32-byte key wrapped in a second OCTET STRING (CurvePrivateKey).
    private static byte[] Pkcs8(byte oid, byte[] privateKey) =>
        [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, oid,
         0x04, 0x22, 0x04, 0x20, .. privateKey];

    // RFC 5958 OneAsymmetricKey v2 (IMPLICIT tags): version 1, the curve's AlgorithmIdentifier, the key as a
    // CurvePrivateKey, [0] attributes holding a friendlyName (PKCS#9), and [1] the public key.
    private static byte[] OneAsymmetricKeyV2(byte oid, byte[] privateKey, byte[] publicKey)
    {
        var curvePrivateKey = new AsnWriter(AsnEncodingRules.DER);
        curvePrivateKey.WriteOctetString(privateKey);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            using (writer.PushSequence())
                writer.WriteObjectIdentifier($"1.3.101.{oid}");
            writer.WriteOctetString(curvePrivateKey.Encode());
            using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.9.20"); // friendlyName
                using (writer.PushSetOf())
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, "Curdle Chairs");
            }
            writer.WriteBitString(publicKey, tag: new Asn1Tag(TagClass.ContextSpecific, 1));
        }
        return writer.Encode();
    }

    // Reads a wrapped Curve25519 key as RFC 8410 has it, refusing anything else: version 0, or version 1
    // (RFC 5958 OneAsymmetricKey v2), the curve's OID with no parameters, the 32-byte key in a
    // CurvePrivateKey OCTET STRING inside privateKey, optional [0] attributes, the [1] public key only in
    // version 1, and nothing after. Returns the private key and the public key when the token included it.
    private static (byte[] PrivateKey, byte[]? PublicKey) ReadCurvePrivateKey(byte[] pkcs8, byte oid)
    {
        var outer = new AsnReader(pkcs8, AsnEncodingRules.DER);
        AsnReader info = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        Assert.True(info.TryReadInt32(out int version) && version is 0 or 1, $"PKCS#8 version {version}");
        AsnReader algorithm = info.ReadSequence();
        Assert.Equal($"1.3.101.{oid}", algorithm.ReadObjectIdentifier());
        Assert.False(algorithm.HasData, "RFC 8410 AlgorithmIdentifier has no parameters");

        var curvePrivateKey = new AsnReader(info.ReadOctetString(), AsnEncodingRules.DER);
        byte[] privateKey = curvePrivateKey.ReadOctetString();
        curvePrivateKey.ThrowIfNotEmpty();
        Assert.Equal(32, privateKey.Length);

        Asn1Tag attributes = new(TagClass.ContextSpecific, 0, isConstructed: true);
        if (info.HasData && info.PeekTag().HasSameClassAndValue(attributes))
            info.ReadEncodedValue();

        byte[]? publicKey = null;
        if (info.HasData)
        {
            Assert.Equal(1, version);
            publicKey = info.ReadBitString(out int unusedBits, new Asn1Tag(TagClass.ContextSpecific, 1));
            Assert.Equal(0, unusedBits);
            Assert.Equal(32, publicKey.Length);
        }
        info.ThrowIfNotEmpty();
        return (privateKey, publicKey);
    }

    // A wrap of the key holding expectedPrivate: its public key, when the token includes one, must be
    // expectedPublic (pass null when there is no reference for it).
    private static void AssertWrapsTheKey(byte[] pkcs8, byte oid, byte[] expectedPrivate, byte[]? expectedPublic)
    {
        var (privateKey, publicKey) = ReadCurvePrivateKey(pkcs8, oid);
        Assert.Equal(expectedPrivate, privateKey);
        if (publicKey is not null && expectedPublic is not null)
            Assert.Equal(expectedPublic, publicKey);
    }

    // An AES-256 key imported from a value the test holds, wrapping and unwrapping with
    // CKM_AES_CBC_PAD; Wrap returns the decrypted PKCS#8 and Unwrap encrypts it here first.
    private sealed class Kek : IDisposable
    {
        private readonly Pkcs11SessionCore _session;
        private readonly Aes _aes = Aes.Create();
        private readonly byte[] _iv = RandomNumberGenerator.GetBytes(16);
        private readonly ObjectHandle _handle;

        public Kek(Pkcs11SessionCore session)
        {
            _session = session;
            _aes.Key = RandomNumberGenerator.GetBytes(32);
            _handle = TestKeys.ImportAesWrappingKey(session, _aes.Key);
        }

        private Mechanism CbcPad => new(CKM.CKM_AES_CBC_PAD, _iv);

        public void Dispose() => _aes.Dispose();

        public byte[] Wrap(ObjectHandle privateKey) =>
            _aes.DecryptCbc(_session.WrapKey(CbcPad, _handle, privateKey), _iv, PaddingMode.PKCS7);

        // Extractable, so a case can wrap the result again.
        public ObjectHandle Unwrap(byte[] pkcs8, CKK keyType, CKA usage)
        {
            using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var use = new ObjectAttribute(usage, true);
            byte[] wrapped = _aes.EncryptCbc(pkcs8, _iv, PaddingMode.PKCS7);
            return _session.UnwrapKey(CbcPad, _handle, wrapped, [cls, type, token, sensitive, extractable, use]);
        }
    }

    // A session key pair whose private half may be wrapped (sensitive, but extractable); returns it.
    private static ObjectHandle GenerateWrappablePrivateKey(
        Pkcs11SessionCore session, CKM mechanism, CKK keyType, byte[] ecParams, CKA usage)
    {
        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubType = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privType = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var privUsage = new ObjectAttribute(usage, true);

        session.GenerateKeyPair(new Mechanism(mechanism),
            [pubClass, pubType, pubToken, pubParams],
            [privClass, privType, privToken, privSensitive, privExtractable, privUsage],
            out _, out var priv);
        return priv;
    }

    private static void AssertUsage(Pkcs11SessionCore session, ObjectHandle key, CKK keyType, bool sign, bool derive)
    {
        using var attrs = session.GetAttributeValue(key, [CKA.CKA_KEY_TYPE, CKA.CKA_SIGN, CKA.CKA_DERIVE]);
        Assert.Equal((ulong)keyType, attrs[0].GetValueAsUlong());
        Assert.Equal(sign, attrs[1].GetValueAsBool());
        Assert.Equal(derive, attrs[2].GetValueAsBool());
    }

    // Agrees a raw (CKD_NULL) secret with peerPublic as a generic secret the token can MAC with, and
    // returns HMAC-SHA256 of Message under it.
    private static byte[] HmacUnderSharedSecret(Pkcs11SessionCore session, ObjectHandle privateKey, byte[] peerPublic)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var macSign = new ObjectAttribute(CKA.CKA_SIGN, true);
        var ecdh = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peerPublic));
        ObjectHandle secret = session.DeriveKey(ecdh, privateKey, [cls, type, token, length, macSign]);
        return session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), secret, Message);
    }
}
