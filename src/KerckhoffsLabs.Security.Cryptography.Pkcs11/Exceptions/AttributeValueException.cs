using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Exception with the name of PKCS#11 attribute whose value could not be read or converted
/// </summary>
/// <remarks>
/// Derives from <see cref="CryptographicException"/>: attribute reads happen underneath the
/// BCL-shaped façades (resolving a key's type or parameters before an operation), so this can
/// surface from a plain <c>SignData</c> call and has to be catchable the same way.
/// </remarks>
public sealed class AttributeValueException : CryptographicException
{
    /// <summary>
    /// Attribute whose value could not be read or converted
    /// </summary>
    public CKA Attribute { get; }

    /// <summary>
    /// Initializes new instance of AttributeValueException class
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    public AttributeValueException(CKA attribute)
        : base(string.Format("Value of attribute {0} could not be read", attribute))
    {
        Attribute = attribute;
    }

    /// <summary>
    /// Initializes a new instance of AttributeValueException class with a reference to the inner exception that is the cause of this exception
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    /// <param name="innerException">The exception that is the cause of the current exception</param>
    public AttributeValueException(CKA attribute, Exception innerException)
        : base(string.Format("Value of attribute {0} could not be converted", attribute), innerException)
    {
        Attribute = attribute;
    }

    /// <summary>
    /// Initializes new instance of AttributeValueException class with a caller-supplied explanation.
    /// </summary>
    /// <remarks>
    /// For refusals that need to say more than "could not be read" — chiefly a module reporting a
    /// value length the library will not act on, where the reason matters more than the attribute.
    /// </remarks>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    /// <param name="message">Explanation of why the value was not read</param>
    public AttributeValueException(ulong attribute, string message)
        : base(message)
    {
        Attribute = (CKA)attribute;
    }

    /// <summary>
    /// Initializes new instance of AttributeValueException class
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    public AttributeValueException(uint attribute)
        : this((CKA)attribute)
    {

    }

    /// <summary>
    /// Initializes a new instance of AttributeValueException class with a reference to the inner exception that is the cause of this exception
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    /// <param name="innerException">The exception that is the cause of the current exception</param>
    public AttributeValueException(uint attribute, Exception innerException)
        : this((CKA)attribute, innerException)
    {

    }

    /// <summary>
    /// Initializes new instance of AttributeValueException class
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    public AttributeValueException(ulong attribute)
        : this((CKA)Convert.ToUInt32(attribute))
    {

    }

    /// <summary>
    /// Initializes a new instance of AttributeValueException class with a reference to the inner exception that is the cause of this exception
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    /// <param name="innerException">The exception that is the cause of the current exception</param>
    public AttributeValueException(ulong attribute, Exception innerException)
        : this((CKA)Convert.ToUInt32(attribute), innerException)
    {

    }
}
