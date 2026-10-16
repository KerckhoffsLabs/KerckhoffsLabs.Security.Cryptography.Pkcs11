using System.Formats.Asn1;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>The Edwards and Montgomery curves of RFC 8410, by the name the backend tests pass.</summary>
public enum EcxCurve
{
    Ed25519,
    Ed448,
    X25519,
    X448,
}

/// <summary>
/// Backend-agnostic tests for the <c>CKA_PUBLIC_KEY_INFO</c> of Edwards (<see cref="CKK.CKK_EC_EDWARDS"/>)
/// and Montgomery (<see cref="CKK.CKK_EC_MONTGOMERY"/>) keys. RFC 8410 §4 fixes the SubjectPublicKeyInfo of
/// Ed25519, Ed448, X25519 and X448: the curve's AlgorithmIdentifier with its parameters absent, and the
/// raw public key as the BIT STRING, with no unused bits and no inner OCTET STRING. A token that encodes it
/// any other way hands out a public key OpenSSL and other tokens cannot read.
/// </summary>
/// <remarks>
/// <para>
/// Each case generates a key pair and compares the <c>CKA_PUBLIC_KEY_INFO</c> of both halves (PKCS#11
/// v3.0 defines it on public and private keys) with an RFC 8410 SubjectPublicKeyInfo built here, around
/// the public key the token reports in <c>CKA_EC_POINT</c>. That attribute is the raw key on some tokens and
/// the key in a DER OCTET STRING on others; either form is accepted, and the raw key is what goes in the
/// expected encoding.
/// </para>
/// <para>
/// A case skips when the token does not provide <c>CKA_PUBLIC_KEY_INFO</c> on either half (PKCS#11 lets it
/// leave the attribute empty), when it lacks the curve's key-pair generation mechanism, and when it refuses
/// the curve itself.
/// </para>
/// </remarks>
internal static class EcxPublicKeyInfoTestCases
{
    internal static void Assert_PublicKeyInfo_IsRfc8410(IPkcs11Backend backend, EcxCurve curve)
    {
        (CKM generate, CKK keyType, string oid, int keyLength, CKA usage) = Describe(curve);
        backend.RequireMechanisms(generate);

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            // Key generation for every curve is the setup here, not what is under test, so the session
            // runs under AllowInsecure rather than let a policy decide which curves are checked.
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                (ObjectHandle pub, ObjectHandle priv) = Generate(session, generate, keyType, oid, usage, curve);

                byte[] publicKey = RawPublicKey(session, pub, keyLength, curve);
                byte[] expected = Spki(oid, publicKey);

                byte[]? fromPublic = PublicKeyInfo(session, pub);
                byte[]? fromPrivate = PublicKeyInfo(session, priv);
                if (fromPublic is null && fromPrivate is null)
                    Assert.Skip($"The token provides no CKA_PUBLIC_KEY_INFO for a {curve} key.");

                if (fromPublic is not null)
                    Assert.True(expected.AsSpan().SequenceEqual(fromPublic),
                        $"{curve} public key CKA_PUBLIC_KEY_INFO is not RFC 8410's.\n" +
                        $"  token:    {Convert.ToHexString(fromPublic)}\n  RFC 8410: {Convert.ToHexString(expected)}");
                if (fromPrivate is not null)
                    Assert.True(expected.AsSpan().SequenceEqual(fromPrivate),
                        $"{curve} private key CKA_PUBLIC_KEY_INFO is not RFC 8410's.\n" +
                        $"  token:    {Convert.ToHexString(fromPrivate)}\n  RFC 8410: {Convert.ToHexString(expected)}");
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // RFC 8410 §3: id-X25519 1.3.101.110, id-X448 1.3.101.111, id-Ed25519 1.3.101.112, id-Ed448 1.3.101.113.
    private static (CKM Generate, CKK KeyType, string Oid, int KeyLength, CKA Usage) Describe(EcxCurve curve) => curve switch
    {
        EcxCurve.Ed25519 => (CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK.CKK_EC_EDWARDS, "1.3.101.112", 32, CKA.CKA_SIGN),
        EcxCurve.Ed448 => (CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK.CKK_EC_EDWARDS, "1.3.101.113", 57, CKA.CKA_SIGN),
        EcxCurve.X25519 => (CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKK.CKK_EC_MONTGOMERY, "1.3.101.110", 32, CKA.CKA_DERIVE),
        EcxCurve.X448 => (CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKK.CKK_EC_MONTGOMERY, "1.3.101.111", 56, CKA.CKA_DERIVE),
        _ => throw new ArgumentOutOfRangeException(nameof(curve)),
    };

    private static (ObjectHandle Public, ObjectHandle Private) Generate(
        Pkcs11SessionCore session, CKM mechanism, CKK keyType, string oid, CKA usage, EcxCurve curve)
    {
        var ecParams = new AsnWriter(AsnEncodingRules.DER);
        ecParams.WriteObjectIdentifier(oid);

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubType = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams.Encode());
        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privType = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privUsage = new ObjectAttribute(usage, true);
        try
        {
            session.GenerateKeyPair(new Mechanism(mechanism),
                [pubClass, pubType, pubToken, pubParams],
                [privClass, privType, privToken, privUsage],
                out ObjectHandle pub, out ObjectHandle priv);
            return (pub, priv);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_CURVE_NOT_SUPPORTED
                                         or CKR.CKR_DOMAIN_PARAMS_INVALID or CKR.CKR_ATTRIBUTE_VALUE_INVALID)
        {
            Assert.Skip($"The token does not generate {curve} keys ({ex.ReturnValue}).");
            throw; // unreachable: Assert.Skip throws
        }
    }

    // CKA_EC_POINT holds the raw key, or the raw key in a DER OCTET STRING; returns the raw key.
    private static byte[] RawPublicKey(Pkcs11SessionCore session, ObjectHandle pub, int keyLength, EcxCurve curve)
    {
        using var attrs = session.GetAttributeValue(pub, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead, $"{curve} CKA_EC_POINT cannot be read.");
        byte[] point = attrs[0].GetValueAsByteArray();
        if (point.Length == keyLength)
            return point;

        byte[] inner = AsnDecoder.ReadOctetString(point, AsnEncodingRules.DER, out int consumed);
        Assert.Equal(point.Length, consumed);
        Assert.Equal(keyLength, inner.Length);
        return inner;
    }

    // Null when the token does not provide the attribute: unreadable, or empty as PKCS#11 allows.
    private static byte[]? PublicKeyInfo(Pkcs11SessionCore session, ObjectHandle key)
    {
        using var attrs = session.GetAttributeValue(key, [CKA.CKA_PUBLIC_KEY_INFO]);
        if (attrs[0].CannotBeRead)
            return null;
        byte[] value = attrs[0].GetValueAsByteArray();
        return value.Length == 0 ? null : value;
    }

    // RFC 8410 §4: SEQUENCE { SEQUENCE { curve OID }, BIT STRING <raw public key> }.
    private static byte[] Spki(string oid, byte[] publicKey)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
                writer.WriteObjectIdentifier(oid);
            writer.WriteBitString(publicKey);
        }
        return writer.Encode();
    }
}
