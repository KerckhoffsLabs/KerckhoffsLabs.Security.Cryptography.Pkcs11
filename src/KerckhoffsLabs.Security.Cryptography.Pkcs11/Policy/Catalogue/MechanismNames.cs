using System.Collections.Frozen;
using System.Globalization;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// Names mechanisms in denial messages and the generated catalogue documentation.
/// </summary>
/// <remarks>
/// <see cref="CKM"/> carries spec aliases — two names for one value (<c>CKM_ECDSA_KEY_PAIR_GEN</c> /
/// <c>CKM_EC_KEY_PAIR_GEN</c>, <c>CKM_CAST5_*</c> / <c>CKM_CAST128_*</c>, …) — and <see cref="Enum.ToString()"/>
/// picks one of them arbitrarily. <see cref="Of"/> always returns the current PKCS#11 v3 name instead.
/// </remarks>
internal static class MechanismNames
{
    /// <summary>The preferred name for each aliased <see cref="CKM"/> value.</summary>
    private static readonly FrozenDictionary<CKM, string> Preferred = new Dictionary<CKM, string>
    {
        [CKM.CKM_CAST128_KEY_GEN] = nameof(CKM.CKM_CAST128_KEY_GEN),
        [CKM.CKM_CAST128_ECB] = nameof(CKM.CKM_CAST128_ECB),
        [CKM.CKM_CAST128_CBC] = nameof(CKM.CKM_CAST128_CBC),
        [CKM.CKM_CAST128_MAC] = nameof(CKM.CKM_CAST128_MAC),
        [CKM.CKM_CAST128_MAC_GENERAL] = nameof(CKM.CKM_CAST128_MAC_GENERAL),
        [CKM.CKM_CAST128_CBC_PAD] = nameof(CKM.CKM_CAST128_CBC_PAD),
        [CKM.CKM_PBE_MD5_CAST128_CBC] = nameof(CKM.CKM_PBE_MD5_CAST128_CBC),
        [CKM.CKM_PBE_SHA1_CAST128_CBC] = nameof(CKM.CKM_PBE_SHA1_CAST128_CBC),
        [CKM.CKM_EC_KEY_PAIR_GEN] = nameof(CKM.CKM_EC_KEY_PAIR_GEN),
        [CKM.CKM_DSA_PROBABILISTIC_PARAMETER_GEN] = nameof(CKM.CKM_DSA_PROBABILISTIC_PARAMETER_GEN),
        [CKM.CKM_SHA3_224_KEY_DERIVE] = nameof(CKM.CKM_SHA3_224_KEY_DERIVE),
        [CKM.CKM_SHA3_256_KEY_DERIVE] = nameof(CKM.CKM_SHA3_256_KEY_DERIVE),
        [CKM.CKM_SHA3_384_KEY_DERIVE] = nameof(CKM.CKM_SHA3_384_KEY_DERIVE),
        [CKM.CKM_SHA3_512_KEY_DERIVE] = nameof(CKM.CKM_SHA3_512_KEY_DERIVE),
        [CKM.CKM_SHAKE_128_KEY_DERIVE] = nameof(CKM.CKM_SHAKE_128_KEY_DERIVE),
        [CKM.CKM_SHAKE_256_KEY_DERIVE] = nameof(CKM.CKM_SHAKE_256_KEY_DERIVE),
    }.ToFrozenDictionary();

    /// <summary>The name to show for <paramref name="mechanism"/>: its current PKCS#11 v3 name when it has aliases.</summary>
    public static string Of(CKM mechanism)
        => Preferred.TryGetValue(mechanism, out string? name) ? name : mechanism.ToString();

    /// <summary>
    /// Describes a <c>CK_MECHANISM_TYPE</c>: the <see cref="CKM"/> name when the value is a defined
    /// member, otherwise <c>"vendor mechanism 0x…"</c>.
    /// </summary>
    public static string Describe(CKM mechanism)
        => Enum.IsDefined(mechanism)
            ? Of(mechanism)
            : "vendor mechanism 0x" + ((ulong)mechanism).ToString("X", CultureInfo.InvariantCulture);
}

/// <summary>Names key types in denial messages and the generated catalogue documentation.</summary>
/// <remarks>
/// <see cref="CKK"/> carries two spec aliases (<c>CKK_ECDSA</c> / <c>CKK_EC</c>, <c>CKK_CAST5</c> /
/// <c>CKK_CAST128</c>), and <see cref="Enum.ToString()"/> picks one of them arbitrarily.
/// </remarks>
internal static class KeyTypeNames
{
    /// <summary>The name to show for <paramref name="keyType"/>: its current PKCS#11 v3 name when it has an alias.</summary>
    public static string Of(CKK keyType) => keyType switch
    {
        CKK.CKK_EC => nameof(CKK.CKK_EC),
        CKK.CKK_CAST128 => nameof(CKK.CKK_CAST128),
        _ => keyType.ToString(),
    };
}
