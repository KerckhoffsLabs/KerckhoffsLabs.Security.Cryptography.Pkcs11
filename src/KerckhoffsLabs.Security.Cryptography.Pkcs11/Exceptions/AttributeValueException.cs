using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Exception with the name of PKCS#11 attribute whose value could not be read or converted
/// </summary>
public sealed class AttributeValueException : Exception
{
    /// <summary>
    /// Attribute whose value could not be read or converted
    /// </summary>
    private readonly CKA _attribute = CKA.CKA_VENDOR_DEFINED;

    /// <summary>
    /// Attribute whose value could not be read or converted
    /// </summary>
    public CKA Attribute => _attribute;

    /// <summary>
    /// Initializes new instance of AttributeValueException class
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    public AttributeValueException(CKA attribute)
        : base(string.Format("Value of attribute {0} could not be read", attribute.ToString()))
    {
        _attribute = attribute;
    }

    /// <summary>
    /// Initializes a new instance of AttributeValueException class with a reference to the inner exception that is the cause of this exception
    /// </summary>
    /// <param name="attribute">Attribute whose value could not be read or converted</param>
    /// <param name="innerException">The exception that is the cause of the current exception</param>
    public AttributeValueException(CKA attribute, Exception innerException)
        : base(string.Format("Value of attribute {0} could not be converted", attribute.ToString()), innerException)
    {
        _attribute = attribute;
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
