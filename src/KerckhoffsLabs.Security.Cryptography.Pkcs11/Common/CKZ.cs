using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Salt/Encoding parameter sources
/// </summary>
public static class CKZ
{
    /// <summary>
    /// PKCS #1 RSA OAEP: Encoding parameter specified
    /// </summary>
    public static readonly NativeCULong CKZ_DATA_SPECIFIED = new (0x00000001);

    /// <summary>
    /// PKCS #5 PBKDF2 Key Generation: Salt specified
    /// </summary>
    public static readonly NativeCULong CKZ_SALT_SPECIFIED = new (0x00000001);
}