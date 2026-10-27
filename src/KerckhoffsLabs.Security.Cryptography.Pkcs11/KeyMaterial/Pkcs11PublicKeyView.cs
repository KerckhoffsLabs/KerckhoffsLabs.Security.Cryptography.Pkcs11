using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// Reads a managed public-key view off a token key, from whichever handle a <see cref="Pkcs11Key"/> has.
/// The read from a private-key object alone, for a key with no public companion, is
/// <c>Internal.PublicKeySynthesis</c>.
/// </summary>
internal static class Pkcs11PublicKeyView
{
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

        if (!EcPointEncoding.TryParsePublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray(), out ECParameters ec))
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                $"{operationName} (CKA_EC_POINT / CKA_EC_PARAMS could not be parsed as a named-curve uncompressed point)");
        return ec;
    }
}
