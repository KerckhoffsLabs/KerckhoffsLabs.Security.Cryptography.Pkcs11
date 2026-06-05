using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// HMAC primitives over a CKK_GENERIC_SECRET key. The C_SignInit/C_Sign/C_Verify entry points that
// drive these live in ManagedSoftToken.Sign.cs, which dispatches HMAC vs asymmetric by mechanism.
internal sealed partial class ManagedSoftToken
{
    private static bool IsHmac(CKM m) => m is
        CKM.CKM_SHA_1_HMAC or CKM.CKM_SHA256_HMAC or CKM.CKM_SHA384_HMAC or CKM.CKM_SHA512_HMAC
        or CKM.CKM_SHA3_256_HMAC or CKM.CKM_SHA3_384_HMAC or CKM.CKM_SHA3_512_HMAC;

    private static byte[] ComputeHmac(CKM mech, byte[] key, byte[] data) => mech switch
    {
        CKM.CKM_SHA_1_HMAC => HMACSHA1.HashData(key, data),
        CKM.CKM_SHA256_HMAC => HMACSHA256.HashData(key, data),
        CKM.CKM_SHA384_HMAC => HMACSHA384.HashData(key, data),
        CKM.CKM_SHA512_HMAC => HMACSHA512.HashData(key, data),
        CKM.CKM_SHA3_256_HMAC => HMACSHA3_256.HashData(key, data),
        CKM.CKM_SHA3_384_HMAC => HMACSHA3_384.HashData(key, data),
        CKM.CKM_SHA3_512_HMAC => HMACSHA3_512.HashData(key, data),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported HMAC {mech}."),
    };
}
