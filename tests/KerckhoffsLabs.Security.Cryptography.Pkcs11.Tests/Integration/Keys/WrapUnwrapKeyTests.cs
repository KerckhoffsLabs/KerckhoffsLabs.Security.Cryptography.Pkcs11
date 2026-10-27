using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

internal static class WrapUnwrapKeyTestCases
{
    // CKM_AES_KEY_WRAP_PKCS7 is a Recommended documented refusal (non-standard padding, not RFC 5649), so its
    // cases opt in for the wrap / unwrap calls; the RFC 3394 / 5649 variants run under the default policy.
    // Secure key defaults on unwrap do not depend on the policy, so the opt-in does not mask them.
    private static IDisposable? OptInIfRefusedByDefault(Pkcs11SessionCore session, CKM wrapMechanism)
        => wrapMechanism == CKM.CKM_AES_KEY_WRAP_PKCS7 ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;

    internal static void Assert_AesKeyWrap_RoundTrip(IPkcs11Backend backend, CKM wrapMechanism)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            // KEK can stay non-extractable — it's the wrapping key, not wrapped.
            ObjectHandle kek = TestKeys.GenerateAes256WrappingKey(session);

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
            var keyGenMech = new Mechanism(CKM.CKM_AES_KEY_GEN);
            // The weakened template needs the opt-in, but only for this call: a helper-wide scope
            // would still be open inside the test body and would mask an assertion that the gate
            // fires there.
            ObjectHandle dataKey;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                dataKey = session.GenerateKey(keyGenMech, dkTemplate);

            try
            {
                // Encrypt a known plaintext with the original data key.
                byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
                byte[] plaintext = Encoding.UTF8.GetBytes("phase-4a wrap round-trip plaintext");
                byte[] ciphertext = TestAesGcm.Encrypt(session, dataKey, iv, plaintext);

                var wrapMech = new Mechanism(wrapMechanism);
                using IDisposable? optIn = OptInIfRefusedByDefault(session, wrapMechanism);
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
                    byte[] recovered = TestAesGcm.Decrypt(session, unwrapped, iv, ciphertext);
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
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // Sets up a logged-in session with a 256-bit KEK and an extractable AES data key wrapped under
    // it, runs <paramref name="body"/> with (session, kek, wrappedBytes), then tears everything down.
    private static void WithWrappedAesKey(IPkcs11Backend backend, CKM wrapMechanism, Action<Pkcs11SessionCore, ObjectHandle, byte[]> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle kek = TestKeys.GenerateAes256WrappingKey(session);
            using var dkClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var dkKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var dkValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var dkToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var dkSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var dkExtract = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            var dkTemplate = new List<ObjectAttribute> { dkClass, dkKeyType, dkValueLen, dkToken, dkSensitive, dkExtract };
            var keyGenMech = new Mechanism(CKM.CKM_AES_KEY_GEN);
            // The weakened template needs the opt-in, but only for this call: a helper-wide scope
            // would still be open inside the test body and would mask an assertion that the gate
            // fires there.
            ObjectHandle dataKey;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                dataKey = session.GenerateKey(keyGenMech, dkTemplate);
            try
            {
                var wrapMech = new Mechanism(wrapMechanism);
                using IDisposable? optIn = OptInIfRefusedByDefault(session, wrapMechanism);
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
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    /// <summary>
    /// Unwrapping without CKA_SENSITIVE / CKA_EXTRACTABLE must yield a sensitive, non-extractable key: the
    /// flags read back as the library set them, and the token acts on them, refusing to reveal the value or
    /// wrap it out.
    /// </summary>
    /// <remarks>
    /// openCryptoki accepted the two attributes in an unwrap template from 10f48c5 but overwrote them with
    /// CKA_SENSITIVE = FALSE and CKA_EXTRACTABLE = TRUE until 2345b3c7, so this case failed there.
    /// </remarks>
    /// <param name="backend">The backend under test.</param>
    /// <param name="wrapMechanism">The AES key-wrap mechanism.</param>
    /// <param name="unextractableCode">
    /// What <c>C_WrapKey</c> answers for the non-extractable key: <see cref="CKR.CKR_KEY_UNEXTRACTABLE"/>, as
    /// PKCS#11 has it, unless the backend is known to answer otherwise.
    /// </param>
    internal static void Assert_Unwrap_AppliesSecureDefaults(IPkcs11Backend backend, CKM wrapMechanism,
        CKR unextractableCode = CKR.CKR_KEY_UNEXTRACTABLE)
    {
        WithWrappedAesKey(backend, wrapMechanism, (session, kek, wrapped) =>
        {
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            // Deliberately omit CKA_SENSITIVE / CKA_EXTRACTABLE — the library must supply them.
            var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken };
            var wrapMech = new Mechanism(wrapMechanism);

            ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
            try
            {
                using var read = session.GetAttributeValue(unwrapped, [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE]);
                Assert.True(read.First(a => a.Type == CKA.CKA_SENSITIVE).GetValueAsBool(),
                    "unwrapped key should default to CKA_SENSITIVE=true");
                Assert.False(read.First(a => a.Type == CKA.CKA_EXTRACTABLE).GetValueAsBool(),
                    "unwrapped key should default to CKA_EXTRACTABLE=false");

                using var value = session.GetAttributeValue(unwrapped, [CKA.CKA_VALUE]);
                Assert.True(value[0].CannotBeRead, "a sensitive key's CKA_VALUE must not be readable");
                var refused = Assert.ThrowsAny<Pkcs11Exception>(() => session.WrapKey(wrapMech, kek, unwrapped));
                Assert.Equal(unextractableCode, refused.ReturnValue);
            }
            finally { session.DestroyObject(unwrapped); }
        });
    }

    /// <summary>
    /// An explicit <c>CKA_EXTRACTABLE=true</c> is permitted without opting in, and the resulting key
    /// really is extractable: it wraps again to the bytes it was unwrapped from, every AES key wrap being
    /// deterministic.
    /// </summary>
    /// <remarks>
    /// It used to be refused. Requiring an "insecure" opt-in to unwrap into a wrappable key described
    /// a safe operation as a dangerous one — the value never leaves the token in the clear, which is
    /// what <c>CKA_SENSITIVE</c> governs and what the gate still refuses.
    /// </remarks>
    internal static void Assert_Unwrap_ExplicitExtractable_IsAllowed(IPkcs11Backend backend, CKM wrapMechanism)
    {
        WithWrappedAesKey(backend, wrapMechanism, (session, kek, wrapped) =>
        {
            var wrapMech = new Mechanism(wrapMechanism);

            using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var t = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var ex = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            {
                var template = new List<ObjectAttribute> { c, k, t, ex };
                ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    using var read = session.GetAttributeValue(unwrapped, [CKA.CKA_EXTRACTABLE]);
                    Assert.True(read.First(a => a.Type == CKA.CKA_EXTRACTABLE).GetValueAsBool());
                    Assert.Equal(wrapped, session.WrapKey(wrapMech, kek, unwrapped));
                }
                finally { session.DestroyObject(unwrapped); }
            }
        });
    }

    /// <summary>
    /// A secret key's <c>CKA_VALUE</c> is readable only when the key is neither sensitive nor unextractable
    /// (PKCS#11 v3.2 §5.7), whatever combination the template asked for, and the flags read back as set.
    /// </summary>
    /// <remarks>
    /// A module revealed the value of a non-sensitive but unextractable key, and its <c>C_CreateObject</c>
    /// ignored the template's <c>CKA_SENSITIVE</c> and <c>CKA_EXTRACTABLE</c>.
    /// </remarks>
    /// <param name="backend">The backend under test.</param>
    /// <param name="unextractableValueIsReadable">
    /// Whether the token reveals the value of a non-sensitive key whatever its <c>CKA_EXTRACTABLE</c>, taking the
    /// attribute to govern wrapping only. Pinned where a backend is known to, so a change shows here.
    /// </param>
    internal static void Assert_KeyValue_IsReadableOnlyWhenNonSensitiveAndExtractable(
        IPkcs11Backend backend, bool unextractableValueIsReadable = false)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        // Non-sensitive keys are a deliberately weakened template.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        try
        {
            byte[] raw = RandomNumberGenerator.GetBytes(32);
            foreach (var (sensitive, extractable) in ((bool, bool)[])[(false, false), (true, true), (false, true)])
            {
                using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var t = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var s = new ObjectAttribute(CKA.CKA_SENSITIVE, sensitive);
                using var x = new ObjectAttribute(CKA.CKA_EXTRACTABLE, extractable);
                using var e = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var v = new ObjectAttribute(CKA.CKA_VALUE, raw);
                ObjectHandle key = session.CreateObject([c, k, t, s, x, e, v]);
                try
                {
                    using var flags = session.GetAttributeValue(key, [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE]);
                    Assert.Equal(sensitive, flags.First(a => a.Type == CKA.CKA_SENSITIVE).GetValueAsBool());
                    Assert.Equal(extractable, flags.First(a => a.Type == CKA.CKA_EXTRACTABLE).GetValueAsBool());

                    using var value = session.GetAttributeValue(key, [CKA.CKA_VALUE]);
                    if (sensitive || (!extractable && !unextractableValueIsReadable))
                        Assert.True(value[0].CannotBeRead, $"CKA_VALUE of a key with CKA_SENSITIVE={sensitive}, CKA_EXTRACTABLE={extractable} was readable.");
                    else
                        Assert.Equal(raw, value[0].GetValueAsByteArray());
                }
                finally { session.DestroyObject(key); }
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    /// <summary>
    /// <c>CKM_AES_KEY_WRAP</c> wraps and unwraps a key longer than 256 bytes: a 320-byte HMAC key comes back
    /// with the same value, which an HMAC computed on the token with the unwrapped key shows.
    /// </summary>
    /// <remarks>
    /// A module unwrapped into a fixed 256-byte buffer, so it refused valid blobs for longer keys.
    /// </remarks>
    internal static void Assert_AesKeyWrap_KeyOver256Bytes_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_KEY_WRAP, f => f.Wrap && f.Unwrap, "CKF_WRAP and CKF_UNWRAP");
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle kek = TestKeys.GenerateAes256WrappingKey(session);
            byte[] raw = RandomNumberGenerator.GetBytes(320);
            ObjectHandle secret;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            using (var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY))
            using (var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET))
            using (var t = new ObjectAttribute(CKA.CKA_TOKEN, false))
            using (var x = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true))
            using (var s = new ObjectAttribute(CKA.CKA_SIGN, true))
            using (var v = new ObjectAttribute(CKA.CKA_VALUE, raw))
            {
                try
                {
                    secret = session.CreateObject([c, k, t, x, s, v]);
                }
                catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_KEY_SIZE_RANGE or CKR.CKR_ATTRIBUTE_VALUE_INVALID)
                {
                    session.DestroyObject(kek);
                    Assert.Skip($"The token does not hold a 320-byte generic secret ({ex.ReturnValue}).");
                    throw; // unreachable: Assert.Skip throws
                }
            }
            try
            {
                var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
                byte[] wrapped = session.WrapKey(wrapMech, kek, secret);
                Assert.Equal(raw.Length + 8, wrapped.Length);

                using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var k = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
                using var t = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var s = new ObjectAttribute(CKA.CKA_SIGN, true);
                ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, [c, k, t, s]);
                try
                {
                    byte[] mac = session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), unwrapped, "over 256 bytes"u8);
                    Assert.Equal(HMACSHA256.HashData(raw, "over 256 bytes"u8), mac);
                }
                finally { session.DestroyObject(unwrapped); }
            }
            finally
            {
                session.DestroyObject(secret);
                session.DestroyObject(kek);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    /// <summary>
    /// An EC private key whose PKCS#8 carries no public point, which RFC 5915 makes optional (and the
    /// parameters too, the AlgorithmIdentifier naming the curve), unwraps to a key that signs for that point.
    /// </summary>
    /// <remarks>
    /// NSS refused it with <c>CKR_KEY_TYPE_INCONSISTENT</c> until 3.132 (Bug 2082671). The key is wrapped here,
    /// under an AES key the test holds, with <c>CKM_AES_CBC_PAD</c>, the wrap every backend offers for private
    /// keys, so the session opts in to it.
    /// </remarks>
    /// <param name="backend">The backend under test.</param>
    /// <param name="ecParamsInTemplate">
    /// Whether the unwrap template names the curve in <c>CKA_EC_PARAMS</c>. PKCS#11 says it must not (the
    /// footnote 6 attributes come from the wrapped key), so only a token that requires it anyway passes true.
    /// </param>
    internal static void Assert_Unwrap_EcPrivateKeyWithoutPublicPoint_Signs(IPkcs11Backend backend, bool ecParamsInTemplate = false)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CBC_PAD, f => f.Unwrap, "CKF_UNWRAP");
        backend.RequireMechanism(CKM.CKM_ECDSA);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] pkcs8 = EcPkcs8WithoutPublicPoint(ec.ExportParameters(includePrivateParameters: true).D!);
        using var aes = Aes.Create();
        aes.Key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] wrapped = aes.EncryptCbc(pkcs8, iv, PaddingMode.PKCS7);

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            ObjectHandle kek = TestKeys.ImportAesWrappingKey(session, aes.Key);
            using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
            using var ecParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
            List<ObjectAttribute> template = ecParamsInTemplate ? [cls, type, token, sign, ecParams] : [cls, type, token, sign];
#pragma warning disable KLPKCS11009 // CBC-PAD is the private-key wrap under test (see the remarks).
            ObjectHandle key = session.UnwrapKey(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), kek, wrapped, template);
#pragma warning restore KLPKCS11009
            try
            {
                byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes("signed by an unwrapped EC key"));
                byte[] signature = session.Sign(new Mechanism(CKM.CKM_ECDSA), key, digest);
                Assert.True(ec.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            }
            finally
            {
                session.DestroyObject(key);
                session.DestroyObject(kek);
            }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // A P-256 PrivateKeyInfo whose ECPrivateKey holds the version and the private key only (RFC 5915 §3).
    private static byte[] EcPkcs8WithoutPublicPoint(byte[] d)
    {
        var ecPrivateKey = new AsnWriter(AsnEncodingRules.DER);
        using (ecPrivateKey.PushSequence())
        {
            ecPrivateKey.WriteInteger(1);
            ecPrivateKey.WriteOctetString(d);
        }

        var info = new AsnWriter(AsnEncodingRules.DER);
        using (info.PushSequence())
        {
            info.WriteInteger(0);
            using (info.PushSequence())
            {
                info.WriteObjectIdentifier("1.2.840.10045.2.1");    // id-ecPublicKey
                info.WriteObjectIdentifier("1.2.840.10045.3.1.7");  // prime256v1
            }
            info.WriteOctetString(ecPrivateKey.Encode());
        }
        return info.Encode();
    }
}
