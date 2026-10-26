using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>The size of a token asymmetric key, for the asymmetric adapters' <c>KeySize</c> and <c>LegalKeySizes</c>.</summary>
internal static class AsymmetricKeySize
{
    /// <summary>The curve of an EC key, from <see cref="Pkcs11Key.ReadEcCurve"/>.</summary>
    /// <returns><see langword="null"/> when the library's catalog doesn't list it or <c>C_GetAttributeValue</c>
    /// fails: the adapter keeps its base class's default.</returns>
    public static Pkcs11CurveInfo? TryReadEcCurve(Pkcs11Key key)
    {
        try
        {
            return key.ReadEcCurve();
        }
        catch (Pkcs11Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// The legal sizes of a token key: its own size alone. A token-resident key has exactly one size and
    /// cannot be resized, so this reports that size rather than a range the token may not support.
    /// </summary>
    public static KeySizes[] Only(int bits) => [new KeySizes(bits, bits, 0)];
}
