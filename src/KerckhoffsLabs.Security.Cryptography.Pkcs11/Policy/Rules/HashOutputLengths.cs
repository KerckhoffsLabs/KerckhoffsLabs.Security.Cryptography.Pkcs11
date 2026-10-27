using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Rules;

/// <summary>Output length, in bytes, of the hashes a parameter check may name; bounds an RSA-PSS salt.</summary>
internal static class HashOutputLengths
{
    private static readonly FrozenDictionary<CKM, int> Lengths = new Dictionary<CKM, int>
    {
        [CKM.CKM_SHA_1] = 20,
        [CKM.CKM_SHA224] = 28,
        [CKM.CKM_SHA256] = 32,
        [CKM.CKM_SHA384] = 48,
        [CKM.CKM_SHA512] = 64,
        [CKM.CKM_SHA512_224] = 28,
        [CKM.CKM_SHA512_256] = 32,
        [CKM.CKM_SHA3_224] = 28,
        [CKM.CKM_SHA3_256] = 32,
        [CKM.CKM_SHA3_384] = 48,
        [CKM.CKM_SHA3_512] = 64,
    }.ToFrozenDictionary();

    public static bool IsKnown(CKM hash) => Lengths.ContainsKey(hash);

    public static int Of(CKM hash) => Lengths[hash];
}
