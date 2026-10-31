using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

#pragma warning disable KLPKCS11012 // opting in to each raw-output kind is the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>
/// Backend-agnostic tests of the raw-output entry points behind the explicit export opt-in:
/// <see cref="Pkcs11Key.DeriveRawSecret"/> on X25519 / X448 (<see cref="CKK.CKK_EC_MONTGOMERY"/>) keys, and
/// <see cref="Pkcs11Key.DeriveBytes"/>. Each case runs under <c>Recommended</c> with
/// <see cref="KeyMaterialExportRule.Allow"/> for its kind only, so it also shows that the opt-in is all such
/// a read-back needs.
/// </summary>
/// <remarks>
/// <para>
/// The .NET BCL has no X25519 or X448, so the agreement cases use RFC 7748's §6.1 and §6.2 vectors: Alice's
/// private key is imported into the token and agrees with Bob's public key, and the secret must be the RFC's.
/// A case skips unless the token advertises <c>CKM_EC_MONTGOMERY_KEY_PAIR_GEN</c> and
/// <c>CKM_ECDH1_DERIVE</c> (SoftHSM2 has no <see cref="CKK.CKK_EC_MONTGOMERY"/>), and when it refuses the curve
/// on import.
/// </para>
/// <para>
/// Keys are imported under <see cref="CryptoPolicy.AllowInsecure"/>, extractable and non-sensitive: the test
/// knows their values anyway, and NSS refuses to derive a key more accessible than its base
/// (<c>CKR_KEY_FUNCTION_NOT_PERMITTED</c>).
/// </para>
/// </remarks>
internal static class RawOutputTestCases
{
    // RFC 7748 §6.1 (X25519) and §6.2 (X448): Alice's private key, Bob's public key, the shared secret.
    private static readonly Rfc7748Vector X25519 = new(
        "X25519", "1.3.101.110",
        Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

    private static readonly Rfc7748Vector X448 = new(
        "X448", "1.3.101.111",
        Convert.FromHexString(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"),
        Convert.FromHexString(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"),
        Convert.FromHexString(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"));

    private sealed record Rfc7748Vector(string Name, string Oid, byte[] AlicePrivate, byte[] BobPublic, byte[] Shared);

    // SP 800-108 feedback mode, HMAC-SHA256: base key, label, context, IV, and an output longer than one
    // HMAC block so the chaining value is used.
    private static readonly byte[] KdfBaseKey = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f");
    private static readonly byte[] KdfLabel = "kl-raw-output-label"u8.ToArray();
    private static readonly byte[] KdfContext = "kl-raw-output-context"u8.ToArray();
    private static readonly byte[] KdfIv = Convert.FromHexString("00112233445566778899aabbccddeeff");
    private const int KdfOutputLength = 42;

    private static ICryptoPolicy OptIn(KeyMaterialExportKind kind) =>
        CryptoPolicy.Recommended.ToBuilder("Raw-output opt-in")
            .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([kind], "Integration test of the raw-output entry points."))
            .Build();

    // === X25519 / X448 DeriveRawSecret ==========================================================

    internal static void Assert_X25519_DeriveRawSecret_MatchesBcl(IPkcs11Backend backend) => AssertAgreesTheRfc7748Secret(backend, X25519);

    internal static void Assert_X448_DeriveRawSecret_MatchesBcl(IPkcs11Backend backend) => AssertAgreesTheRfc7748Secret(backend, X448);

    private static void AssertAgreesTheRfc7748Secret(IPkcs11Backend backend, Rfc7748Vector vector) =>
        WithAlice(backend, vector, alice =>
        {
            byte[] z = alice.DeriveRawSecret(Spki(vector.Oid, vector.BobPublic));

            Assert.Equal(Convert.ToHexString(vector.Shared), Convert.ToHexString(z));
        });

    // Review Focus 5: an X448 peer for an X25519 key is refused before the token sees it.
    internal static void Assert_X25519_WrongCurvePeer_Throws(IPkcs11Backend backend) =>
        WithAlice(backend, X25519, alice =>
            Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(Spki(X448.Oid, X448.BobPublic))));

    // Review Focus 5: u = 0 would give an all-zero secret whatever the private key; it is refused, never returned.
    internal static void Assert_X25519_ZeroPeer_Throws(IPkcs11Backend backend) =>
        WithAlice(backend, X25519, alice =>
            Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(Spki(X25519.Oid, new byte[32]))));

    // Imports Alice's RFC 7748 private key and hands it to the body under the EcdhSharedSecret opt-in.
    private static void WithAlice(IPkcs11Backend backend, Rfc7748Vector vector, Action<Pkcs11Key> body)
    {
        backend.RequireMechanisms(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE);
        using var session = backend.OpenSession();
        string label = $"kl-raw-{vector.Name}-{Guid.NewGuid():N}";
        try
        {
            Pkcs11Key alice;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                alice = ImportAlice(session, backend, vector, label);
            using (alice)
            using (session.UsePolicy(OptIn(KeyMaterialExportKind.EcdhSharedSecret)))
                body(alice);
        }
        finally
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                DestroyByLabel(session, label);
        }
    }

    private static Pkcs11Key ImportAlice(Pkcs11Session session, IPkcs11Backend backend, Rfc7748Vector vector, string label)
    {
        var ecParams = new AsnWriter(AsnEncodingRules.DER);
        ecParams.WriteObjectIdentifier(vector.Oid);
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_EC_MONTGOMERY)
            .Label(label).Id(Encoding.ASCII.GetBytes(label)).Derive()
            .Attribute(CKA.CKA_EC_PARAMS, ecParams.Encode()).Attribute(CKA.CKA_VALUE, vector.AlicePrivate)
            .Extractable().Sensitive(false)
            .OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            return session.ImportKey(template);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_CURVE_NOT_SUPPORTED or CKR.CKR_DOMAIN_PARAMS_INVALID
                                         or CKR.CKR_ATTRIBUTE_VALUE_INVALID or CKR.CKR_TEMPLATE_INCONSISTENT)
        {
            Assert.Skip($"The token does not import {vector.Name} private keys ({ex.ReturnValue}).");
            throw; // unreachable: Assert.Skip throws
        }
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

    // === DeriveBytes ===========================================================================

    internal static void Assert_DeriveBytes_Sp800108Feedback_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SHA256_HMAC);
        using var session = backend.OpenSession();
        string label = $"kl-raw-kdf-{Guid.NewGuid():N}";
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(KdfBaseKey).Derive().Extractable().Sensitive(false).OnToken(backend.SupportsTokenObjects).Build();
        // Iteration variable K(i-1), then [i]_32, Label || 0x00 || Context, [L]_32 with L the output in bits.
        var mechanism = new Mechanism(CKM.CKM_SP800_108_FEEDBACK_KDF, CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC)
            .IterationCounter()
            .OptionalCounter()
            .ByteArray(KdfLabel)
            .ByteArray([0x00])
            .ByteArray(KdfContext)
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .WithIV(KdfIv)
            .Build());
        try
        {
            Pkcs11Key baseKey;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                baseKey = session.ImportKey(template);
            using (baseKey)
            using (session.UsePolicy(OptIn(KeyMaterialExportKind.KdfOutput)))
            {
                byte[] output = baseKey.DeriveBytes(mechanism, KdfOutputLength);

                Assert.Equal(Convert.ToHexString(ReferenceFeedback()), Convert.ToHexString(output));
            }
        }
        finally
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                DestroyByLabel(session, label);
        }
    }

    // NIST SP 800-108 §5.2, feedback mode with the counter: K(0) = IV, K(i) = HMAC(KI, K(i-1) || [i]_32 ||
    // Label || 0x00 || Context || [L]_32), the output K(1) || K(2) || … cut to L bits.
    private static byte[] ReferenceFeedback()
    {
        var output = new List<byte>();
        byte[] k = KdfIv;
        for (uint i = 1; output.Count < KdfOutputLength; i++)
        {
            var input = new List<byte>(k);
            input.AddRange(BigEndian(i));
            input.AddRange(KdfLabel);
            input.Add(0x00);
            input.AddRange(KdfContext);
            input.AddRange(BigEndian(KdfOutputLength * 8));
            k = HMACSHA256.HashData(KdfBaseKey, input.ToArray());
            output.AddRange(k);
        }
        return [.. output.Take(KdfOutputLength)];
    }

    private static byte[] BigEndian(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }
}
