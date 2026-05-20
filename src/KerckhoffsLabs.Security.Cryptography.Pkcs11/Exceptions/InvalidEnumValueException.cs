namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Thrown when a raw integer value coming from a PKCS#11 module cannot be
/// mapped to a defined member of the expected CK* enum. Always indicates a
/// protocol violation by the module — never an application bug — and should
/// be allowed to propagate.
/// </summary>
/// <remarks>
/// Initializes a new <see cref="InvalidEnumValueException"/>.
/// </remarks>
/// <param name="enumType">The enum type being targeted.</param>
/// <param name="rawValue">The raw value that failed validation.</param>
public sealed class InvalidEnumValueException(Type enumType, ulong rawValue) : Exception($"Value 0x{rawValue:X} is not a defined member of {enumType.Name}")
{
    /// <summary>
    /// The enum type that the raw value was being converted to.
    /// </summary>
    public Type EnumType { get; } = enumType;

    /// <summary>
    /// The raw integer value that did not match any defined enum member.
    /// </summary>
    public ulong RawValue { get; } = rawValue;
}
