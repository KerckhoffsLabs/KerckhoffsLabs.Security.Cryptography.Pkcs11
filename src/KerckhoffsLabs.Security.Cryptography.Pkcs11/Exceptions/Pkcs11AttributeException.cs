using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when the value of a PKCS#11 attribute could not be read or converted: it is sensitive or
/// unextractable, or its length does not fit the requested type.
/// </summary>
/// <remarks>
/// Derives from <see cref="CryptographicException"/>: attribute reads happen underneath the
/// BCL-shaped façades (resolving a key's type or parameters before an operation), so this can
/// surface from a plain <c>SignData</c> call and has to be catchable the same way.
/// </remarks>
/// <param name="attribute">
/// The attribute whose value could not be read or converted. A vendor-defined attribute is its value
/// cast to <see cref="CKA"/>.
/// </param>
/// <param name="message">
/// Explanation of why the value was not read. When <see langword="null"/>, a default naming the
/// attribute is used.
/// </param>
/// <param name="innerException">The exception that caused this one, if any.</param>
public sealed class Pkcs11AttributeException(CKA attribute, string? message = null, Exception? innerException = null)
    : CryptographicException(message ?? DefaultMessage(Describe(attribute), innerException), innerException)
{
    /// <summary>The attribute whose value could not be read or converted.</summary>
    public CKA Attribute { get; } = attribute;

    /// <summary>Names an attribute for a message: the enum name if defined, otherwise the hex code.</summary>
    internal static string Describe(CKA attribute)
        => Enum.IsDefined(attribute) ? attribute.ToString() : $"CKA 0x{(ulong)attribute:X8}";

    private static string DefaultMessage(string attribute, Exception? innerException)
        => innerException is null
            ? $"Value of attribute {attribute} could not be read"
            : $"Value of attribute {attribute} could not be converted";
}
