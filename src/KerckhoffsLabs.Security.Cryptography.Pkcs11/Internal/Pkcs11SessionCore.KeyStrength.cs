using System.Globalization;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Whether the effective policy asks to see the keys it judges (<see cref="ICryptoPolicy.InspectsKeys"/>).
    /// A policy that leaves it at its default does not; the session then reads nothing from the token to
    /// describe a key.
    /// </summary>
    private bool InspectsKeys => _effectivePolicy.InspectsKeys;

    /// <summary>
    /// Submits the strength of the key <paramref name="key"/> points at to the policy, before the token is
    /// asked to use it. Does nothing unless the policy inspects keys.
    /// </summary>
    /// <remarks>
    /// Nothing is cached: a handle can be reused for a different key (destroyed and recreated, or another
    /// session's object), so each guarded call reads the key the handle names now. The read is one
    /// <c>C_GetAttributeValue</c> call (see <see cref="ReadKeyStrength"/>), and only under an inspecting policy.
    /// </remarks>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the key.</exception>
    /// <param name="key">The key the operation uses.</param>
    /// <param name="source">Where the description comes from: <see cref="KeyStrengthSource.ExistingKey"/> here.</param>
    /// <param name="operation">
    /// The operation the key is about to be used for, which a policy may judge a key by (an old key allowed to verify
    /// only); <see langword="null"/> when the use is not one operation.
    /// </param>
    internal void EnforceKeyStrength(ObjectHandle key, KeyStrengthSource source, CryptoOperation? operation)
    {
        if (!InspectsKeys)
            return;

        Enforce(ReadKeyStrength(key, source, operation));
    }

    /// <summary>
    /// Describes <paramref name="key"/> from the token: its <c>CKA_KEY_TYPE</c>, the size attribute its type is judged
    /// by, and for an RSA or EC key its modulus or curve. A value the token will not report becomes
    /// <see langword="null"/>, which an inspecting policy can refuse, so an unreadable key fails closed at the policy
    /// rather than being left to the token. A device or session error propagates, which stops the operation too.
    /// </summary>
    /// <remarks>
    /// One call asks for the type, the size attributes and the lengths of the modulus and the domain parameters
    /// (<see cref="KeyStrengthAttributeReader"/>): a key has the ones its type uses, and the token answers the others as
    /// absent, each on its own (PKCS#11 v3.2 C_GetAttributeValue). An RSA or EC key's modulus or domain parameters are then
    /// read in a second call, into a buffer of exactly the length reported. A module that leaves the type or what that
    /// type is judged by unanswered is asked again for that attribute alone, and is judged the same; an attribute the
    /// token answers as absent is not asked for again. Nothing is cached: a handle can name another key later.
    /// </remarks>
    private KeyStrengthRequest ReadKeyStrength(ObjectHandle key, KeyStrengthSource source, CryptoOperation? operation = null)
    {
        using var _ = AcquireExclusive();
        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue");

        CKR rv = KeyStrengthAttributeReader.Read(_pkcs11Library, _sessionId, (NativeCULong)key.ObjectId, out KeyStrengthAttributeValues read);
        if (rv is CKR.CKR_OBJECT_HANDLE_INVALID or CKR.CKR_KEY_HANDLE_INVALID)
            return new KeyStrengthRequest(null, source) { Operation = operation };
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE or CKR.CKR_BUFFER_TOO_SMALL))
            ThrowIfError(rv, OpGetAttributeValue);

        ulong? type = read.KeyType ?? (read.IsUnanswered(UnansweredAttributes.KeyType) ? ReadUlongOrNull(key, CKA.CKA_KEY_TYPE) : null);
        CKK? keyType = type is { } t ? (CKK)t : null;
        CKA? size = SizeAttributeOf(keyType);
        (ulong? value, UnansweredAttributes slot) = size switch
        {
            CKA.CKA_VALUE_LEN => (read.ValueLen, UnansweredAttributes.ValueLen),
            CKA.CKA_PARAMETER_SET => (read.ParameterSet, UnansweredAttributes.ParameterSet),
            CKA.CKA_HSS_LEVELS => (read.HssLevels, UnansweredAttributes.HssLevels),
            _ => (null, UnansweredAttributes.None),
        };
        if (size is { } attribute && value is null && read.IsUnanswered(slot))
            value = ReadUlongOrNull(key, attribute);

        KeyStrengthRequest request = Describe(keyType, source, size, value) with { Operation = operation };
        return keyType switch
        {
            CKK.CKK_RSA => request with
            {
                ModulusBits = BitLength(ReadValueOrNull(key, CKA.CKA_MODULUS, read.ModulusLength,
                    read.IsUnanswered(UnansweredAttributes.Modulus))),
            },
            CKK.CKK_EC => request with
            {
                Curve = NamedCurveOf(ReadValueOrNull(key, CKA.CKA_EC_PARAMS, read.EcParamsLength,
                    read.IsUnanswered(UnansweredAttributes.EcParams))),
            },
            _ => request,
        };
    }

    // The length in bits of a big-endian integer, leading zero bytes ignored; null when there is none.
    private static int? BitLength(byte[]? bigEndian)
    {
        if (bigEndian is null)
            return null;
        int first = Array.FindIndex(bigEndian, b => b != 0);
        if (first < 0)
            return null;
        return ((bigEndian.Length - first - 1) * 8) + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)bigEndian[first]));
    }

    // The named curve CKA_EC_PARAMS gives, or null for explicit domain parameters or bytes that are not a curve OID.
    private static Pkcs11ECCurve? NamedCurveOf(byte[]? ecParams)
    {
        if (ecParams is null)
            return null;
        try
        {
            return Pkcs11ECCurve.FromEcParams(ecParams);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    // The value of a byte-array attribute whose length the one-call read reported: read into a buffer of exactly that
    // length, never a guess a module could copy past (KeyStrengthAttributeReader). An unanswered length, or a value that
    // did not come back at that length, is read again through the generic reader. Null when the token does not report it.
    private byte[]? ReadValueOrNull(ObjectHandle key, CKA attribute, int? length, bool unanswered)
    {
        if (length is not { } exact)
            return unanswered ? ReadBytesOrNull(key, attribute) : null;

        CKR rv = KeyStrengthAttributeReader.ReadExact(_pkcs11Library, _sessionId, (NativeCULong)key.ObjectId, attribute, exact,
            out byte[]? value);
        if (value is not null)
            return value;
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE or CKR.CKR_BUFFER_TOO_SMALL
            or CKR.CKR_OBJECT_HANDLE_INVALID or CKR.CKR_KEY_HANDLE_INVALID))
            ThrowIfError(rv, OpGetAttributeValue);
        return rv == CKR.CKR_BUFFER_TOO_SMALL ? ReadBytesOrNull(key, attribute) : null;
    }

    // One byte-array attribute through the generic reader (its length, then its value): for a length the one-call read
    // left unanswered, or a value that changed length between the two calls. Null when the token does not report it.
    private byte[]? ReadBytesOrNull(ObjectHandle key, CKA attribute)
    {
        try
        {
            using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(key, [attribute]);
            return attrs[0].CannotBeRead ? null : attrs[0].GetValueAsByteArray();
        }
        catch (Pkcs11AttributeException)
        {
            return null;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_OBJECT_HANDLE_INVALID or CKR.CKR_KEY_HANDLE_INVALID)
        {
            return null;
        }
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
    /// certificate, data object or profile has no strength to judge and is neither pre- nor post-checked. Every
    /// <c>CKA_CLASS</c> entry counts, so a <c>CKO_DATA</c> listed before a key class cannot hide the key. A
    /// template with no class, or with a class that is not a readable <c>CK_ULONG</c>, is treated as a key, so
    /// the token's answer decides.
    /// </summary>
    private static bool CreatesKey(IReadOnlyList<ObjectAttribute>? template)
    {
        if (template is null)
            return true;

        bool statesAClass = false;
        foreach (ObjectAttribute attribute in template.Where(a => a.Type == CKA.CKA_CLASS))
        {
            statesAClass = true;
            if (UlongOrNull(attribute) is not { } objectClass
                || (CKO)objectClass is CKO.CKO_SECRET_KEY or CKO.CKO_PRIVATE_KEY or CKO.CKO_PUBLIC_KEY)
                return true;
        }
        return !statesAClass;
    }

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
        StringBuilder? failures = null;
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
            (failures ??= new StringBuilder()).Append(
                CultureInfo.InvariantCulture,
                $" The refused key (handle {handle.ObjectId}) could not be destroyed and remains on the token: {rv}.");
        }
        return failures?.ToString() ?? string.Empty;
    }

    // A CKA_VALUE_LEN of 0 or beyond int is no key's length: reported as unknown, which a strict policy refuses.
    // SoftHSM2 reports 0 on unwrapped secret keys, so the refusal says the length was not reported rather than
    // judging a real key as zero bytes long.
    private static int? LengthOf(ulong? valueLen) => valueLen is { } len and > 0 and <= int.MaxValue ? (int)len : null;

    /// <summary>
    /// <see cref="ReadUlongsOrNull"/> for one attribute: its value, or <see langword="null"/> when the token does
    /// not report it, or does not know the handle.
    /// </summary>
    /// <exception cref="Pkcs11Exception">The read failed for a reason other than the value being unavailable.</exception>
    private ulong? ReadUlongOrNull(ObjectHandle key, CKA attribute)
    {
        Span<ulong?> value = stackalloc ulong?[1];
        ReadUlongsOrNull(key, [attribute], value);
        return value[0];
    }

    /// <summary>
    /// <c>CK_ULONG</c> attributes of <paramref name="key"/>, in one <c>C_GetAttributeValue</c> call: each value, or
    /// <see langword="null"/> when the token does not report it: unreadable (sensitive, unknown to the object), a
    /// value of <c>CK_UNAVAILABLE_INFORMATION</c>, or the wrong length.
    /// </summary>
    /// <remarks>
    /// Only those answers say "this value is not available", which an inspecting policy refuses as unreported; so
    /// does a handle the token does not know, which leaves every value <see langword="null"/>. Any other failure of the
    /// read (a device, session or library error) is the token's error, not the key's: it propagates, still before the
    /// operation the read guards reaches the token.
    /// </remarks>
    /// <exception cref="Pkcs11Exception">The read failed for a reason other than the value being unavailable.</exception>
    private void ReadUlongsOrNull(ObjectHandle key, ReadOnlySpan<CKA> attributes, Span<ulong?> values)
    {
        using var _ = AcquireExclusive();
        Log.SessionTrace(_logger, (ulong)_sessionId, "GetAttributeValue");

        CKR rv = UlongAttributeReader.Read(_pkcs11Library, _sessionId, (NativeCULong)key.ObjectId, attributes, values);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL or CKR.CKR_OBJECT_HANDLE_INVALID or CKR.CKR_KEY_HANDLE_INVALID))
            ThrowIfError(rv, OpGetAttributeValue);
    }
}
