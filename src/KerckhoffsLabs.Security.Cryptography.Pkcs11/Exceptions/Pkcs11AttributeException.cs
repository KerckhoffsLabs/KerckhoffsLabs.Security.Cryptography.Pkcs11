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
/// <param name="attribute">The attribute whose value could not be read or converted.</param>
/// <param name="message">
/// Explanation of why the value was not read. When <see langword="null"/>, a default naming the
/// attribute is used.
/// </param>
/// <param name="innerException">The exception that caused this one, if any.</param>
public sealed class Pkcs11AttributeException(CKA attribute, string? message = null, Exception? innerException = null)
    : CryptographicException(message ?? DefaultMessage(Describe((ulong)attribute), innerException), innerException)
{
    /// <summary>
    /// The attribute whose value could not be read or converted. A vendor attribute code wider than
    /// <see cref="CKA"/> can represent is reported as <see cref="CKA.CKA_VENDOR_DEFINED"/>; the
    /// message carries the full code.
    /// </summary>
    public CKA Attribute { get; } = attribute;

    /// <summary>
    /// Creates the exception for an attribute code as the module reported it, which may be wider than
    /// <see cref="CKA"/> can represent.
    /// </summary>
    internal static Pkcs11AttributeException For(ulong attributeType, string? message = null, Exception? innerException = null)
        => new(
            attributeType <= uint.MaxValue ? (CKA)attributeType : CKA.CKA_VENDOR_DEFINED,
            message ?? DefaultMessage(Describe(attributeType), innerException),
            innerException);

    /// <summary>Names an attribute code for a message: the enum name if defined, otherwise the hex code.</summary>
    internal static string Describe(ulong attributeType)
        => attributeType <= uint.MaxValue && Enum.IsDefined((CKA)attributeType)
            ? ((CKA)attributeType).ToString()
            : $"CKA 0x{attributeType:X8}";

    private static string DefaultMessage(string attribute, Exception? innerException)
        => innerException is null
            ? $"Value of attribute {attribute} could not be read"
            : $"Value of attribute {attribute} could not be converted";
}
