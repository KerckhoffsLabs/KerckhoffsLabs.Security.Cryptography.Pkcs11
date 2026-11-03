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
        CKA? size = SizeAttributeOf(keyType);
        return Describe(keyType, source, size, size is { } attribute ? ReadUlongOrNull(key, attribute) : null);
    }

    /// <summary>
    /// The one attribute that gives the size of a key of <paramref name="keyType"/>, or
    /// <see langword="null"/> for a type described by its type alone.
    /// </summary>
    private static CKA? SizeAttributeOf(CKK? keyType) => keyType switch
    {
        CKK.CKK_AES or CKK.CKK_GENERIC_SECRET or CKK.CKK_HKDF or CKK.CKK_SHA384_HMAC or CKK.CKK_SHA512_HMAC
            => CKA.CKA_VALUE_LEN,
        CKK.CKK_ML_KEM or CKK.CKK_ML_DSA => CKA.CKA_PARAMETER_SET,
        CKK.CKK_HSS => CKA.CKA_HSS_LEVELS,
        _ => null,
    };

    /// <summary>The request for a key of <paramref name="keyType"/> whose <paramref name="size"/> attribute holds <paramref name="value"/>.</summary>
    private static KeyStrengthRequest Describe(CKK? keyType, KeyStrengthSource source, CKA? size, ulong? value) => size switch
    {
        CKA.CKA_VALUE_LEN => new KeyStrengthRequest(keyType, source) { ValueLengthBytes = LengthOf(value) },
        CKA.CKA_PARAMETER_SET => new KeyStrengthRequest(keyType, source) { ParameterSet = value },
        CKA.CKA_HSS_LEVELS => new KeyStrengthRequest(keyType, source) { HssLevels = value },
        _ => new KeyStrengthRequest(keyType, source),
    };

    /// <summary>
    /// The pre-check: submits the strength the caller's <paramref name="template"/> asks for, before the token
    /// creates the key. Does nothing unless the policy inspects keys, and nothing when the template does not
    /// state the key's size (<c>CKA_VALUE_LEN</c>, or the length of a <c>CKA_VALUE</c> being imported;
    /// <c>CKA_PARAMETER_SET</c>; <c>CKA_HSS_LEVELS</c>): the token then picks it, and
    /// <see cref="EnforceCreatedKeyStrength"/> judges what it picked. Every stated size is judged, so a
    /// template that names one twice cannot slip a weak one past the first.
    /// </summary>
    /// <param name="keyType">
    /// The key type the creating mechanism implies (see <see cref="KeyTypeGeneratedBy"/>), or
    /// <see langword="null"/>; the template's own <c>CKA_KEY_TYPE</c> wins.
    /// </param>
    /// <param name="template">The attributes of the key to be created, as the caller gave them.</param>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the size the template states.</exception>
    private void EnforceTemplateKeyStrength(CKK? keyType, IReadOnlyList<ObjectAttribute>? template)
    {
        if (!InspectsKeys || template is null)
            return;

        if (FirstUlongOf(template, CKA.CKA_KEY_TYPE) is { } stated)
            keyType = (CKK)stated;
        if (SizeAttributeOf(keyType) is not { } size)
            return;

        foreach (ObjectAttribute attribute in template)
        {
            if (attribute.Type == size)
                Enforce(Describe(keyType, KeyStrengthSource.Template, size, UlongOrNull(attribute)));
            // A secret key imported with C_CreateObject states its size as the length of its value.
            else if (size == CKA.CKA_VALUE_LEN && attribute.Type == CKA.CKA_VALUE)
                Enforce(Describe(keyType, KeyStrengthSource.Template, size, attribute.CannotBeRead ? null : (ulong)attribute.ValueLength));
        }
    }

    /// <summary>The key type a key-generating mechanism makes, or <see langword="null"/> when it does not imply one.</summary>
    private static CKK? KeyTypeGeneratedBy(CKM mechanism) => mechanism switch
    {
        CKM.CKM_AES_KEY_GEN => CKK.CKK_AES,
        CKM.CKM_GENERIC_SECRET_KEY_GEN => CKK.CKK_GENERIC_SECRET,
        CKM.CKM_ML_KEM_KEY_PAIR_GEN => CKK.CKK_ML_KEM,
        CKM.CKM_ML_DSA_KEY_PAIR_GEN => CKK.CKK_ML_DSA,
        CKM.CKM_HSS_KEY_PAIR_GEN => CKK.CKK_HSS,
        CKM.CKM_XMSS_KEY_PAIR_GEN => CKK.CKK_XMSS,
        _ => null,
    };

    /// <summary>
    /// Whether a <c>C_CreateObject</c> <paramref name="template"/> makes a key. Its <c>CKA_CLASS</c> says so; a
    /// certificate, data object or profile has no strength to judge and is neither pre- nor post-checked. A
    /// template with no readable class is treated as a key, so the token's answer decides.
    /// </summary>
    private static bool CreatesKey(IReadOnlyList<ObjectAttribute>? template)
        => template is null
            || FirstUlongOf(template, CKA.CKA_CLASS) is not { } objectClass
            || (CKO)objectClass is CKO.CKO_SECRET_KEY or CKO.CKO_PRIVATE_KEY or CKO.CKO_PUBLIC_KEY;

    private static ulong? FirstUlongOf(IReadOnlyList<ObjectAttribute> template, CKA type)
    {
        foreach (ObjectAttribute attribute in template)
        {
            if (attribute.Type == type)
                return UlongOrNull(attribute);
        }
        return null;
    }

    // A template value that is not a CK_ULONG is no size: reported as unknown, which a strict policy refuses.
    private static ulong? UlongOrNull(ObjectAttribute attribute)
    {
        try
        {
            ulong value = attribute.GetValueAsUlong();
            return CK.IsCkInformationUnavailable(value) ? null : value;
        }
        catch (Pkcs11AttributeException)
        {
            return null;
        }
    }

    /// <summary>
    /// The post-check: reads back each key the token has just <paramref name="created"/> and submits what the
    /// token actually made. If any is refused, every handle in <paramref name="created"/> is destroyed (both
    /// halves of a pair go together) and none is returned. Does nothing unless the policy inspects keys.
    /// </summary>
    /// <remarks>
    /// The template may have stated nothing (the token chose a default), or a value the token did not honour;
    /// this is the check that covers both, and the reason the template check can let an unstated size through.
    /// A destroy that fails leaves a refused key on the token: the exception then says so and names the handle
    /// (a handle is not secret), and an error is logged, as nobody else can clean it up.
    /// </remarks>
    /// <exception cref="CryptoPolicyViolationException">The policy refused a created key.</exception>
    private void EnforceCreatedKeyStrength(params ReadOnlySpan<ObjectHandle> created)
    {
        if (!InspectsKeys)
            return;

        ICryptoPolicy policy = _effectivePolicy;
        KeyStrengthRequest? refused = null;
        string? reason = null;
        try
        {
            foreach (ObjectHandle handle in created)
            {
                // CK_INVALID_HANDLE names no object: a derivation that returns its keys in the mechanism's
                // parameters (CKM_TLS12_KEY_AND_MAC_DERIVE) leaves it here. There is no key to read or destroy.
                if (handle.IsInvalid)
                    continue;

                KeyStrengthRequest request = ReadKeyStrength(handle, KeyStrengthSource.CreatedKey);
                PolicyDecision decision = policy.Evaluate(request);
                if (!decision.IsAllowed)
                {
                    (refused, reason) = (request, decision.Reason!);
                    break;
                }
            }
        }
        catch
        {
            // Nothing the read or the policy throws may leave an unjudged key behind with no handle returned.
            DestroyRefused(policy, created);
            throw;
        }

        if (refused is null)
            return;

        Log.PolicyDenied(_logger, (ulong)_sessionId, policy.Name, refused.Describe());
        throw new CryptoPolicyViolationException(policy.Name, refused, reason + DestroyRefused(policy, created));
    }

    /// <summary>
    /// Destroys every handle in <paramref name="created"/>, attempting each even when one fails. Returns the
    /// sentences to append to the refusal's reason, one per key that remains on the token.
    /// </summary>
    private string DestroyRefused(ICryptoPolicy policy, ReadOnlySpan<ObjectHandle> created)
    {
        string failures = string.Empty;
        foreach (ObjectHandle handle in created)
        {
            if (handle.IsInvalid)
                continue;

            CKR rv;
            try
            {
                rv = _pkcs11Library.C_DestroyObject(_sessionId, (NativeCULong)handle.ObjectId);
            }
            catch (ObjectDisposedException)
            {
                // The library was finalized under us. The refusal is still the error to report; the key
                // could not be destroyed.
                rv = CKR.CKR_CRYPTOKI_NOT_INITIALIZED;
            }
            if (rv == CKR.CKR_OK)
                continue;

            Log.PolicyCleanupFailed(_logger, (ulong)_sessionId, policy.Name, handle.ObjectId);
            failures += $" The refused key (handle {handle.ObjectId}) could not be destroyed and remains on the token: {rv}.";
        }
        return failures;
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
