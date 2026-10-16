using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Reads a managed public-key view off a token key: from a <c>CKO_PRIVATE_KEY</c> object's attributes
/// when no <c>CKO_PUBLIC_KEY</c> companion is stored on the token (verify-only / encrypt-only paths
/// that need only public material), or from whichever handle a <see cref="Pkcs11Key"/> has.
/// </summary>
internal static class Pkcs11PublicKeyView
{
    /// <summary>
    /// Reads CKA_MODULUS + CKA_PUBLIC_EXPONENT from the private-key object identified by
    /// <paramref name="privateHandle"/> and returns the corresponding
    /// <see cref="RSAParameters"/>. Returns <see langword="null"/> if either attribute is missing
    /// or marked sensitive.
    /// </summary>
    internal static RSAParameters? TrySynthesizeRsa(Pkcs11SessionCore session, ObjectHandle privateHandle)
    {
        using var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        ]);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            return null;

        return new RSAParameters
        {
            Modulus = attrs[0].GetValueAsByteArray(),
            Exponent = attrs[1].GetValueAsByteArray(),
        };
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

    /// <summary>
    /// Reads <paramref name="key"/>'s EC public key (CKA_EC_POINT + CKA_EC_PARAMS) as an
    /// <see cref="ECParameters"/>. <see cref="Pkcs11Key.GetAttributeValue(ReadOnlySpan{CKA})"/> picks the public-key
    /// handle when one exists and falls back to the private-key handle otherwise — covering both real
    /// key-pair companions and private-only objects that carry CKA_EC_POINT / CKA_EC_PARAMS.
    /// </summary>
    /// <param name="key">The token EC key.</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="Pkcs11Exception">
    /// The attributes are sensitive or unreadable, or cannot be parsed as a named-curve uncompressed point.
    /// </exception>
    internal static ECParameters ReadEcPublicKey(Pkcs11Key key, string operationName)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_EC_POINT, CKA.CKA_EC_PARAMS);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                $"{operationName} (CKA_EC_POINT / CKA_EC_PARAMS not readable from any available handle)");

        ECParameters? ec = EcPointEncoding.TryParsePublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
        return ec ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
            $"{operationName} (CKA_EC_POINT / CKA_EC_PARAMS could not be parsed as a named-curve uncompressed point)");
    }
}
