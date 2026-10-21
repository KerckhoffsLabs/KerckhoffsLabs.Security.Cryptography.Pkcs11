using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>The size of a token secret key, for the symmetric adapters' <c>KeySize</c> and <c>LegalKeySizes</c>.</summary>
internal static class SecretKeySize
{
    /// <summary>
    /// The key's size in bits, from <c>CKA_VALUE_LEN</c> (its length in bytes, which is not sensitive), when
    /// the token reports one that <paramref name="isLegalByteLength"/> accepts.
    /// </summary>
    /// <returns><see langword="null"/> otherwise: the adapter keeps its base class's default.</returns>
    public static int? TryReadBits(Pkcs11Key key, Func<int, bool> isLegalByteLength)
    {
        try
        {
            using var attrs = key.GetAttributeValue(CKA.CKA_VALUE_LEN);
            if (attrs.Count > 0 && !attrs[0].CannotBeRead)
            {
                int bytes = (int)attrs[0].GetValueAsUlong();
                if (isLegalByteLength(bytes))
                    return bytes * 8;
            }
        }
        catch (Pkcs11Exception)
        {
            // The token does not expose CKA_VALUE_LEN.
        }
        return null;
    }

    /// <summary>
    /// The legal sizes of a token key: its own size alone. A token key cannot be resized, so setting
    /// <c>KeySize</c> to another then fails the base class's check, rather than changing the size reported
    /// for an unchanged key — as the asymmetric adapters already report.
    /// </summary>
    public static KeySizes[] Only(int bits) => [new KeySizes(bits, bits, 0)];
}
