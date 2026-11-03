using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Whether the effective policy asks to see the keys it judges. Only a <see cref="ComposedCryptoPolicy"/>
    /// with an inspecting key-strength rule does; under any other policy the session reads nothing from the
    /// token to describe a key.
    /// </summary>
    private bool InspectsKeys => _effectivePolicy is ComposedCryptoPolicy { InspectsKeys: true };

    /// <summary>
    /// Submits the strength of the key <paramref name="key"/> points at to the policy, before the token is
    /// asked to use it. Does nothing unless the policy inspects keys.
    /// </summary>
    /// <remarks>
    /// Nothing is cached: a handle can be reused for a different key (destroyed and recreated, or another
    /// session's object), so each guarded call reads the key the handle names now. The reads cost one or
    /// two <c>C_GetAttributeValue</c> sequences, and only under an inspecting policy.
    /// </remarks>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the key.</exception>
    internal void EnforceKeyStrength(ObjectHandle key, KeyStrengthSource source)
    {
        if (!InspectsKeys)
            return;

        Enforce(ReadKeyStrength(key, source));
    }

    /// <summary>
    /// Describes <paramref name="key"/> from the token: its <c>CKA_KEY_TYPE</c>, then the one attribute that
    /// gives the size of a key of that type. A value the token will not report becomes
    /// <see langword="null"/>, which an inspecting policy refuses: the read never throws, so an unreadable
    /// key fails closed at the policy rather than being left to the token.
    /// </summary>
    private KeyStrengthRequest ReadKeyStrength(ObjectHandle key, KeyStrengthSource source)
    {
        CKK? keyType = ReadUlongOrNull(key, CKA.CKA_KEY_TYPE) is { } type ? (CKK)type : null;

        return keyType switch
        {
            CKK.CKK_AES or CKK.CKK_GENERIC_SECRET or CKK.CKK_HKDF or CKK.CKK_SHA384_HMAC or CKK.CKK_SHA512_HMAC
                => new KeyStrengthRequest(keyType, source) { ValueLengthBytes = LengthOf(ReadUlongOrNull(key, CKA.CKA_VALUE_LEN)) },
            CKK.CKK_ML_KEM or CKK.CKK_ML_DSA
                => new KeyStrengthRequest(keyType, source) { ParameterSet = ReadUlongOrNull(key, CKA.CKA_PARAMETER_SET) },
            CKK.CKK_HSS
                => new KeyStrengthRequest(keyType, source) { HssLevels = ReadUlongOrNull(key, CKA.CKA_HSS_LEVELS) },
            _ => new KeyStrengthRequest(keyType, source),
        };
    }

    // A CKA_VALUE_LEN beyond int is no key's length: reported as unknown, which a strict policy refuses.
    private static int? LengthOf(ulong? valueLen) => valueLen is { } len && len <= int.MaxValue ? (int)len : null;

    /// <summary>
    /// One <c>CK_ULONG</c> attribute of <paramref name="key"/>, or <see langword="null"/> when the token does
    /// not report it: unreadable (sensitive, unknown to the object, <c>CK_UNAVAILABLE_INFORMATION</c>), a
    /// value of <c>CK_UNAVAILABLE_INFORMATION</c>, the wrong length, or a failed call.
    /// </summary>
    private ulong? ReadUlongOrNull(ObjectHandle key, CKA attribute)
    {
        try
        {
            using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(key, [attribute]);
            if (attrs[0].CannotBeRead)
                return null;
            ulong value = attrs[0].GetValueAsUlong();
            return CK.IsCkInformationUnavailable(value) ? null : value;
        }
        catch (Exception ex) when (ex is Pkcs11Exception or Pkcs11AttributeException)
        {
            return null;
        }
    }
}
