using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Object class
/// </summary>
public enum CKO : uint
{
    /// <summary>
    /// Data object that holds information defined by an application.
    /// </summary>
    CKO_DATA = 0x00000000,

    /// <summary>
    /// Certificate object that holds public-key or attribute certificates.
    /// </summary>
    CKO_CERTIFICATE = 0x00000001,

    /// <summary>
    /// Public key object that holds public keys.
    /// </summary>
    CKO_PUBLIC_KEY = 0x00000002,

    /// <summary>
    /// Private key object that holds private keys.
    /// </summary>
    CKO_PRIVATE_KEY = 0x00000003,

    /// <summary>
    /// Secret key object that holds secret keys.
    /// </summary>
    CKO_SECRET_KEY = 0x00000004,

    /// <summary>
    /// Hardware feature object that represent features of the device.
    /// </summary>
    CKO_HW_FEATURE = 0x00000005,

    /// <summary>
    /// Domain parameter object that holds public domain parameters.
    /// </summary>
    CKO_DOMAIN_PARAMETERS = 0x00000006,

    /// <summary>
    /// Mechanism object that provides information about mechanisms supported by a device beyond that given by the CK_MECHANISM_INFO structure.
    /// </summary>
    CKO_MECHANISM = 0x00000007,

    /// <summary>
    /// OTP key object that holds secret keys used by OTP tokens.
    /// </summary>
    CKO_OTP_KEY = 0x00000008,

    /// <summary>
    /// Profile object describing supported features (PKCS#11 v3.0 §4.13)
    /// </summary>
    CKO_PROFILE = 0x00000009,

    /// <summary>
    /// Validation object describing certified / validated subsystems (PKCS#11 v3.2)
    /// </summary>
    CKO_VALIDATION = 0x0000000A,

    /// <summary>
    /// Trust object describing certificate-trust policy (PKCS#11 v3.2)
    /// </summary>
    CKO_TRUST = 0x0000000B,



    /// <summary>
    /// Reserved for token vendors.
    /// </summary>
    CKO_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKOExtensions
{
    /// <summary>Converts <see cref="CKO"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKO value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKO"/>. Use only when the
    /// value is trusted; otherwise prefer <see cref="ToCKOChecked"/>.
    /// </summary>
    public static CKO ToCKO(this NativeCULong value)
    {
        return (CKO)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKO"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKO ToCKOChecked(this NativeCULong value)
    {
        CKO result = (CKO)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKO), (ulong)value);
        return result;
    }
}