using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The DigestInfo an RSASSA-PKCS1-v1_5 signature covers (RFC 8017 §9.2), and the combined mechanism that
/// signs the same scheme over the data. Signing a digest the caller computed is raw <c>CKM_RSA_PKCS</c>
/// over this DigestInfo, and the policy judges it as that combined mechanism: the operation is the scheme,
/// which raw <c>CKM_RSA_PKCS</c> over arbitrary input is not.
/// </summary>
internal static class Pkcs1DigestInfo
{
    /// <summary>Encodes the DigestInfo for <paramref name="digest"/>, and names the combined mechanism.</summary>
    /// <exception cref="NotSupportedException"><paramref name="hash"/> is not SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384 or SHA3-512.</exception>
    /// <exception cref="CryptographicException"><paramref name="digest"/> is not the length of a <paramref name="hash"/> digest.</exception>
    public static (CKM Scheme, byte[] DigestInfo) Encode(HashAlgorithmName hash, ReadOnlySpan<byte> digest)
    {
        (CKM scheme, string oid, int length) = hash.Name switch
        {
            "SHA1" => (CKM.CKM_SHA1_RSA_PKCS, Oids.HashAlgorithms.Sha1, 20),
            "SHA224" => (CKM.CKM_SHA224_RSA_PKCS, Oids.HashAlgorithms.Sha224, 28),
            "SHA256" => (CKM.CKM_SHA256_RSA_PKCS, Oids.HashAlgorithms.Sha256, 32),
            "SHA384" => (CKM.CKM_SHA384_RSA_PKCS, Oids.HashAlgorithms.Sha384, 48),
            "SHA512" => (CKM.CKM_SHA512_RSA_PKCS, Oids.HashAlgorithms.Sha512, 64),
            "SHA3-256" => (CKM.CKM_SHA3_256_RSA_PKCS, Oids.HashAlgorithms.Sha3_256, 32),
            "SHA3-384" => (CKM.CKM_SHA3_384_RSA_PKCS, Oids.HashAlgorithms.Sha3_384, 48),
            "SHA3-512" => (CKM.CKM_SHA3_512_RSA_PKCS, Oids.HashAlgorithms.Sha3_512, 64),
            _ => throw new NotSupportedException($"RSA does not support hash {hash.Name}."),
        };
        if (digest.Length != length)
            throw new CryptographicException($"The hash is {digest.Length} bytes; a {hash.Name} digest is {length}.");

        // DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }, with the
        // NULL parameters RFC 8017 §9.2 note 1 specifies.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(oid);
                writer.WriteNull();
            }
            writer.WriteOctetString(digest);
        }
        return (scheme, writer.Encode());
    }
}
