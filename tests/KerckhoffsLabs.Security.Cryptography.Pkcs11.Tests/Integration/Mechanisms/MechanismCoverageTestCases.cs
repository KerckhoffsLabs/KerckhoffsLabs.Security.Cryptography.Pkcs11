using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>
/// Every standard mechanism a token advertises, driven through the library and checked against a reference the
/// test holds: the digests, HMACs and general-length HMACs of every hash; key derivation by a digest, by an
/// encryption, by concatenation and by extraction; the HMAC, Camellia, Poly1305, Salsa20 and BLAKE2b key
/// generators; the AES feedback modes, ciphertext stealing and GMAC; Camellia; Poly1305; the hash-then-sign RSA
/// and ECDSA mechanisms the rest of the suite does not reach; ANSI X9.31 and ISO/IEC 9796 RSA; signatures with
/// message recovery; key wrapping under each cipher; and RSA PKCS#1 v1.5 key encapsulation.
/// </summary>
/// <remarks>
/// <para>
/// The point is the library, not the token: each case sends a mechanism, and where it has one, its parameter, the
/// way a consumer would, and checks what comes back. A token that does not advertise a mechanism skips the case,
/// so one class runs on every backend. Most of these mechanisms are outside the default policy's allow-list, so every
/// case runs under a scoped <see cref="CryptoPolicy.AllowInsecure"/> lease, as a consumer who opted in would; the
/// policy itself is tested elsewhere.
/// </para>
/// <para>
/// References: the .NET runtime where it has the algorithm; published vectors (RFC 1319, RFC 3713, RFC 7693,
/// RFC 8439, FIPS 180-4, the RIPEMD and GOST R 34.11-94 authors' vectors) for the digests and ciphers it lacks;
/// and, for an HMAC over a hash .NET lacks, RFC 2104 built on the token's own digest, which its own known-answer
/// case checks first. A secret the token derives or generates is compared through an HMAC under it, so a token
/// that keeps derived keys sensitive runs the same case.
/// </para>
/// </remarks>
internal static partial class MechanismCoverageTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
    private static readonly byte[] Abc = "abc"u8.ToArray();
    private static readonly byte[] Iv16 = [.. Enumerable.Range(0, 16).Select(i => (byte)i)];

    // Opens a logged-in session for the case under a scoped AllowInsecure lease, and logs it out after. The
    // policy has its own tests; here the mechanism is the subject, and most of these are outside the default
    // allow-list, so each case runs as a consumer who opted in would.
    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            body(session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // A template that disposes its attributes with it.
    private sealed class Template(List<ObjectAttribute> attributes) : IDisposable
    {
        public List<ObjectAttribute> Attributes => attributes;

        public void Dispose()
        {
            foreach (ObjectAttribute attribute in attributes)
                attribute.Dispose();
        }
    }

    // A session secret key of the type given holding the value given, with the usages given.
    private static ObjectHandle CreateSecret(Pkcs11SessionCore session, CKK keyType, byte[] value, params CKA[] usages)
    {
        using var template = new Template(
        [
            new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, keyType),
            new(CKA.CKA_TOKEN, false), new(CKA.CKA_VALUE, value),
            .. usages.Select(u => new ObjectAttribute(u, true)),
        ]);
        return session.CreateObject(template.Attributes);
    }

    // A generic secret of the length asked, which can only MAC: a case compares it through an HMAC under it.
    private static Template MacSecretTemplate(ulong length) => new(
    [
        new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
        new(CKA.CKA_TOKEN, false), new(CKA.CKA_VALUE_LEN, length), new(CKA.CKA_SIGN, true),
    ]);

    // The HMAC-SHA-256 of Message under a key, computed on the token: how a case compares a secret it cannot read.
    private static byte[] HmacUnder(Pkcs11SessionCore session, ObjectHandle key)
        => session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), key, Message);

    // Derives a generic MAC secret of the length given and returns the HMAC-SHA-256 of Message under it.
    private static byte[] HmacOfDerived(Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle baseKey, ulong length)
    {
        ObjectHandle derived;
        using (Template template = MacSecretTemplate(length))
            derived = session.DeriveKey(mechanism, baseKey, template.Attributes);
        try { return HmacUnder(session, derived); }
        finally { session.DestroyObject(derived); }
    }

    private static byte[] ReadAttribute(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsByteArray();
    }

    private static ulong ReadULong(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsUlong();
    }

    // A CK_ULONG as this platform lays it out: the parameter of the general-length MACs and of CKM_SHA512_T
    // (CK_MAC_GENERAL_PARAMS), and of CKM_EXTRACT_KEY_FROM_KEY (CK_EXTRACT_PARAMS).
    private static byte[] NativeULong(ulong value)
    {
        byte[] bytes = new byte[UnmanagedMemory.NativeULongSize];
        if (bytes.Length == sizeof(ulong))
            BitConverter.TryWriteBytes(bytes, value);
        else
            BitConverter.TryWriteBytes(bytes, checked((uint)value));
        return bytes;
    }

    // RFC 2104 HMAC over a hash function the case supplies, with that hash's input block size.
    private static byte[] ReferenceHmac(Func<byte[], byte[]> hash, int blockSize, byte[] key, byte[] message)
    {
        byte[] k = key.Length > blockSize ? hash(key) : key;
        byte[] padded = new byte[blockSize];
        k.CopyTo(padded, 0);
        byte[] inner = [.. padded.Select(b => (byte)(b ^ 0x36)), .. message];
        byte[] outer = [.. padded.Select(b => (byte)(b ^ 0x5C)), .. hash(inner)];
        return hash(outer);
    }

    // A refusal a token gives for a mechanism, parameter or key type it lists but does not take this way.
    private static readonly CKR[] NotTaken =
    [
        CKR.CKR_MECHANISM_INVALID, CKR.CKR_MECHANISM_PARAM_INVALID, CKR.CKR_KEY_TYPE_INCONSISTENT,
        CKR.CKR_TEMPLATE_INCONSISTENT, CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_CURVE_NOT_SUPPORTED,
        CKR.CKR_DOMAIN_PARAMS_INVALID,
    ];

    // Runs create. A refusal as something the token does not take skips with the reason its wrapper declared, and
    // fails when it declared none: a token that lists a mechanism is expected to run it.
    private static T Taken<T>(Func<T> create, string what, string? notTakenBecause = null)
    {
        try { return create(); }
        catch (Pkcs11Exception ex) when (NotTaken.Contains(ex.ReturnValue))
        {
            if (notTakenBecause is null)
                Assert.Fail($"The backend refused {what} ({ex.ReturnValue}); if it does not take it, declare that in its test wrapper.");
            Assert.Skip(notTakenBecause);
            throw;
        }
    }
}
