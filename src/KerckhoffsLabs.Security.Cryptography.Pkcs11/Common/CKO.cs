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
    /// Reserved for token vendors.
    /// </summary>
    CKO_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKOExtensions
{
    /// <summary>
    /// Converts CKO to NativeCULong
    /// </summary>
    /// <param name="value">CKO that should be converted</param>
    /// <returns>NativeCULong with value from CKO</returns>
    public static NativeCULong ToCULong(CKO value)
    {
        return new NativeCULong(Convert.ToUInt32(value));
    }

    /// <summary>
    /// Converts NativeCULong to CKO
    /// </summary>
    /// <param name="value">NativeCULong that should be converted</param>
    /// <returns>CKO with NativeCULong value</returns>
    public static CKO ToCKO(NativeCULong value)
    {
        return (CKO)value.Value;
    }
}