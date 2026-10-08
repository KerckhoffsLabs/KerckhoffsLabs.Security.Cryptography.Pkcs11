using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Output lengths fixed by the mechanism alone: a digest, or a MAC that is not truncated. For these the
/// output can be sized before the call, which saves the length query, one native round trip.
/// </summary>
/// <remarks>
/// Only mechanisms whose length needs nothing else are listed. A signature whose length depends on the key
/// (RSA, ECDSA, EdDSA, ML-DSA) is left out, since finding it would cost an attribute read, and the
/// <c>*_GENERAL</c> MACs are left out because their parameter chooses the length. An entry that is wrong
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
}
