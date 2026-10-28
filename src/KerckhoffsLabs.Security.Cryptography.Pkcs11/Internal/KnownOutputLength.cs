using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Output lengths fixed by the mechanism alone: a digest, or a MAC that is not truncated. For these the
/// output can be sized before the call, which saves the length query, one native round trip.
/// </summary>
/// <remarks>
/// Only mechanisms whose length needs nothing else are listed. A signature whose length depends on the key
/// (RSA, ECDSA, EdDSA, ML-DSA) is left out, since finding it would cost an attribute read, and the
/// <c>*_GENERAL</c> MACs are left out because their parameter chooses the length. EdDSA is still guessed
/// when signing, for NSS's sake (<see cref="OfSignature"/>). An entry that is wrong
/// is still safe: a guess too long is trimmed, one too short is answered with
/// <c>CKR_BUFFER_TOO_SMALL</c> and retried.
/// </remarks>
internal static class KnownOutputLength
{
    /// <summary>The output length of <paramref name="mechanism"/>, or <see langword="null"/> when it is not fixed.</summary>
    public static int? Of(CKM mechanism) => mechanism switch
    {
        CKM.CKM_MD5 or CKM.CKM_MD5_HMAC => 16,
        CKM.CKM_SHA_1 or CKM.CKM_SHA_1_HMAC or CKM.CKM_RIPEMD160 or CKM.CKM_RIPEMD160_HMAC
            or CKM.CKM_BLAKE2B_160 or CKM.CKM_BLAKE2B_160_HMAC => 20,
        CKM.CKM_SHA224 or CKM.CKM_SHA224_HMAC or CKM.CKM_SHA512_224 or CKM.CKM_SHA512_224_HMAC
            or CKM.CKM_SHA3_224 or CKM.CKM_SHA3_224_HMAC => 28,
        CKM.CKM_SHA256 or CKM.CKM_SHA256_HMAC or CKM.CKM_SHA512_256 or CKM.CKM_SHA512_256_HMAC
            or CKM.CKM_SHA3_256 or CKM.CKM_SHA3_256_HMAC or CKM.CKM_BLAKE2B_256 or CKM.CKM_BLAKE2B_256_HMAC => 32,
        CKM.CKM_SHA384 or CKM.CKM_SHA384_HMAC or CKM.CKM_SHA3_384 or CKM.CKM_SHA3_384_HMAC
            or CKM.CKM_BLAKE2B_384 or CKM.CKM_BLAKE2B_384_HMAC => 48,
        CKM.CKM_SHA512 or CKM.CKM_SHA512_HMAC or CKM.CKM_SHA3_512 or CKM.CKM_SHA3_512_HMAC
            or CKM.CKM_BLAKE2B_512 or CKM.CKM_BLAKE2B_512_HMAC => 64,
        CKM.CKM_AES_CMAC => 16,
        CKM.CKM_DES3_CMAC => 8,
        _ => null,
    };

    /// <summary>Ed25519's signature length, RFC 8032 §5.1.6.</summary>
    internal const int Ed25519Signature = 64;

    /// <summary>
    /// The length to size a <c>C_Sign</c> output at for <paramref name="mechanism"/>, or <see langword="null"/>
    /// to query it: <see cref="Of"/>, plus EdDSA guessed at Ed25519's 64 bytes.
    /// </summary>
    /// <remarks>
    /// EdDSA is guessed rather than queried because NSS cannot be queried for it. Its softoken answers the
    /// length query with an ECDSA-sized 144 bytes, then refuses any buffer that is not exactly 64 bytes long
    /// with <c>CKR_ARGUMENTS_BAD</c> (<c>ED_SignMessage</c> in freebl's <c>ec.c</c>), so a client that sizes
    /// the buffer from the query can never sign Ed25519 there
    /// (https://bugzilla.mozilla.org/show_bug.cgi?id=2075850). The guess costs nothing elsewhere: an Ed25519
    /// signature is always 64 bytes, and an Ed448 one (114 bytes) is answered with
    /// <c>CKR_BUFFER_TOO_SMALL</c> and the length, then signed on the second call, as many calls as the query
    /// takes. A module that refuses the guess without reporting the length (opencryptoki's <c>ec_sign</c>) is
    /// then queried, one call more. Safe to remove once a fixed NSS is the oldest one supported.
    /// </remarks>
    public static int? OfSignature(CKM mechanism)
        => mechanism == CKM.CKM_EDDSA ? Ed25519Signature : Of(mechanism);
}
