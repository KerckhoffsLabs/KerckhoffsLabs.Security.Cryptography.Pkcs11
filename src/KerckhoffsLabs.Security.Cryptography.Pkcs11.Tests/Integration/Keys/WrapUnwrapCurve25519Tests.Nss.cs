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
/// Wrapping and unwrapping Ed25519 (<see cref="CKK.CKK_EC_EDWARDS"/>) and X25519
/// (<see cref="CKK.CKK_EC_MONTGOMERY"/>) private keys on NSS. Softoken packs a wrapped private key as
/// PKCS#8, and before 3.131 it had no PKCS#8 form for either curve: <c>C_WrapKey</c> and
/// <c>C_UnwrapKey</c> both failed. 3.131 (Bug 1993638) encodes them as RFC 8410 specifies, the key as
/// a bare <c>CurvePrivateKey</c> OCTET STRING, and gives an unwrapped key the matching key type with
/// <c>CKA_SIGN</c> only (Ed25519) or <c>CKA_DERIVE</c> only (X25519).
/// </summary>
/// <remarks>
/// <para>
/// Every case wraps under an AES key whose value the test holds, so it can decrypt what the token
/// wrapped and compare PKCS#8 bytes. The known-answer cases unwrap the RFC test keys, encoded and
/// encrypted here as a key exported by OpenSSL arrives; the round-trip cases start from a
/// token-generated key. The mechanism list is the same before and after 3.131, so the cases are gated
/// on the softoken release.
/// </para>
/// <para>
/// The Ed25519 cases compare key bytes rather than signatures: NSS reports <c>MAX_ECKEY_LEN * 2</c>
/// as the <c>CKM_EDDSA</c> signature length, then refuses any buffer but exactly 64 bytes with
/// <see cref="CKR.CKR_ARGUMENTS_BAD"/>, so a sign sized from its length query cannot succeed. The
/// X25519 cases do agree a secret: against RFC 7748's, or between the original and the copy.
/// </para>
/// </remarks>
[Collection("Nss")]
public sealed class WrapUnwrapCurve25519Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    private const string Rfc8410Pkcs8 = "PKCS#8 for Ed25519 and X25519 private keys arrived in 3.131 (Bug 1993638)";

    // Last byte of each curve's OID (1.3.101.x) and its DER, as CKA_EC_PARAMS.
    private const byte Ed25519Oid = 0x70;
    private const byte X25519Oid = 0x6E;
    private static readonly byte[] Ed25519Params = [0x06, 0x03, 0x2B, 0x65, Ed25519Oid];
    private static readonly byte[] X25519Params = [0x06, 0x03, 0x2B, 0x65, X25519Oid];

    // RFC 8032 §7.1, TEST 1.
    private static readonly byte[] Rfc8032Test1Secret =
        Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    // RFC 7748 §6.1: Alice's private key, Bob's public key, and the secret they share.
    private static readonly byte[] Rfc7748AlicePrivate =
        Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static readonly byte[] Rfc7748BobPublic =
        Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static readonly byte[] Rfc7748SharedSecret =
        Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    private static readonly byte[] Message = "wrapped Curve25519 key"u8.ToArray();

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_Rfc8410Ed25519Key_WrapsBackToTheSamePkcs8()
    {
        RequireWrapping();
        RunInSession(session =>
        {
            using var kek = new Kek(session);
            byte[] pkcs8 = Pkcs8(Ed25519Oid, Rfc8032Test1Secret);

            ObjectHandle key = kek.Unwrap(pkcs8, CKK.CKK_EC_EDWARDS);

            AssertUsage(session, key, CKK.CKK_EC_EDWARDS, sign: true, derive: false);
            Assert.Equal(pkcs8, kek.Wrap(key));
        });
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret()
    {
        RequireWrapping();
        RequireAgreement();
        RunInSession(session =>
        {
            using var kek = new Kek(session);
            byte[] pkcs8 = Pkcs8(X25519Oid, Rfc7748AlicePrivate);

            ObjectHandle key = kek.Unwrap(pkcs8, CKK.CKK_EC_MONTGOMERY);

            AssertUsage(session, key, CKK.CKK_EC_MONTGOMERY, sign: false, derive: true);
            Assert.Equal(pkcs8, kek.Wrap(key));
            // NSS derives only non-extractable keys, so the secret is compared through an HMAC under it.
            Assert.Equal(HMACSHA256.HashData(Rfc7748SharedSecret, Message),
                         HmacUnderSharedSecret(session, key, Rfc7748BobPublic));
        });
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void WrapUnwrap_Ed25519PrivateKey_KeepsTheKey()
    {
        RequireWrapping();
        _backend.RequireMechanism(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);
        RunInSession(session =>
        {
            using var kek = new Kek(session);
            ObjectHandle original = GenerateWrappablePrivateKey(session, CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK.CKK_EC_EDWARDS, Ed25519Params, CKA.CKA_SIGN);

            byte[] pkcs8 = kek.Wrap(original);
            AssertRfc8410(pkcs8, Ed25519Oid);
            ObjectHandle copy = kek.Unwrap(pkcs8, CKK.CKK_EC_EDWARDS);

            AssertUsage(session, copy, CKK.CKK_EC_EDWARDS, sign: true, derive: false);
            Assert.Equal(pkcs8, kek.Wrap(copy));
        });
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal()
    {
        RequireWrapping();
        RequireAgreement();
        _backend.RequireMechanism(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        RunInSession(session =>
        {
            using var kek = new Kek(session);
            ObjectHandle original = GenerateWrappablePrivateKey(session, CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKK.CKK_EC_MONTGOMERY, X25519Params, CKA.CKA_DERIVE);

            byte[] pkcs8 = kek.Wrap(original);
            AssertRfc8410(pkcs8, X25519Oid);
            ObjectHandle copy = kek.Unwrap(pkcs8, CKK.CKK_EC_MONTGOMERY);

            AssertUsage(session, copy, CKK.CKK_EC_MONTGOMERY, sign: false, derive: true);
            Assert.Equal(HmacUnderSharedSecret(session, original, Rfc7748BobPublic),
                         HmacUnderSharedSecret(session, copy, Rfc7748BobPublic));
        });
    }

    private void RequireWrapping()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        _backend.RequireMechanism(CKM.CKM_AES_CBC_PAD);
    }

    private void RequireAgreement()
    {
        _backend.RequireMechanism(CKM.CKM_ECDH1_DERIVE);
        _backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
    }

    // The session runs under AllowInsecure: CBC wrapping, extractable private keys and a raw CKD_NULL
    // agreement are what is under test, and SecureOnly refuses all three.
    private void RunInSession(Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                body(session);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
        }
    }

    // RFC 8410 §7 OneAsymmetricKey v1: version 0, the curve's AlgorithmIdentifier with no parameters,
    // and the 32-byte key wrapped in a second OCTET STRING (CurvePrivateKey).
    private static byte[] Pkcs8(byte oid, byte[] privateKey) =>
        [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, oid,
         0x04, 0x22, 0x04, 0x20, .. privateKey];

    private static void AssertRfc8410(byte[] pkcs8, byte oid)
    {
        Assert.Equal(48, pkcs8.Length);
        Assert.Equal(Pkcs8(oid, new byte[32])[..16], pkcs8[..16]);
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

        // Names only the class, type and protection: softoken sets CKA_SIGN or CKA_DERIVE from the
        // curve. Extractable, so a case can wrap the result again.
        public ObjectHandle Unwrap(byte[] pkcs8, CKK keyType)
        {
            using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            byte[] wrapped = _aes.EncryptCbc(pkcs8, _iv, PaddingMode.PKCS7);
            return _session.UnwrapKey(CbcPad, _handle, wrapped, [cls, type, token, sensitive, extractable]);
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
