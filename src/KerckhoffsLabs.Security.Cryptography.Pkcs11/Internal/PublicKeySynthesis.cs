using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Reads a public key off a <c>CKO_PRIVATE_KEY</c> object's attributes, for a key with no
/// <c>CKO_PUBLIC_KEY</c> companion on the token (verify-only / encrypt-only paths that need only public
/// material). Works on the private handle directly, so it lives below the façade; the façade-level read
/// that picks whichever handle a key has is <see cref="Pkcs11PublicKeyView"/>.
/// </summary>
internal static class PublicKeySynthesis
{
    /// <summary>
    /// Reads CKA_MODULUS + CKA_PUBLIC_EXPONENT from the private-key object identified by
    /// <paramref name="privateHandle"/> and returns the corresponding
    /// <see cref="RSAParameters"/>. Returns <see langword="null"/> if either attribute is missing
    /// or marked sensitive.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when either value is empty or zero.</exception>
    internal static RSAParameters? TrySynthesizeRsa(Pkcs11SessionCore session, ObjectHandle privateHandle)
    {
        using var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        ]);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            return null;

        const string operation = "Pkcs11Key.Verify";
        return new RSAParameters
        {
            Modulus = RequirePublicInteger(attrs[0].GetValueAsByteArray(), CKA.CKA_MODULUS, operation),
            Exponent = RequirePublicInteger(attrs[1].GetValueAsByteArray(), CKA.CKA_PUBLIC_EXPONENT, operation),
        };
    }

    /// <summary>
    /// A big-endian unsigned integer of a public key, as the token returned it: the RSA modulus or
    /// exponent, a DSA domain parameter or public value. One that is empty or zero belongs to no key, so
    /// it is refused here rather than encoded as one, or handed to the BCL, which fails on an empty one
    /// with an <see cref="IndexOutOfRangeException"/>.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_ATTRIBUTE_VALUE_INVALID"/> when the value is empty or zero.</exception>
    internal static byte[] RequirePublicInteger(byte[] value, CKA attribute, string operation)
    {
        if (value.AsSpan().ContainsAnyExcept((byte)0))
            return value;
        throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
            $"{operation} (the token returned {(value.Length == 0 ? "an empty" : "a zero")} {attribute})");
    }

    /// <summary>
    /// Reads CKA_EC_POINT + CKA_EC_PARAMS from a CKO_PRIVATE_KEY object and returns the
    /// corresponding <see cref="ECParameters"/>. Returns <see langword="null"/> if either attribute
    /// is unreadable (per PKCS#11 v3.1, CKA_EC_POINT is optional on private-key
    /// objects).
    /// </summary>
    internal static ECParameters? TrySynthesizeEc(Pkcs11SessionCore session, ObjectHandle privateHandle)
    {
        using var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_EC_POINT,
            CKA.CKA_EC_PARAMS,
        ]);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            return null;
        return EcPointEncoding.TryParsePublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
    }
}
