namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Salt/Encoding parameter sources
/// </summary>
public static class CKZ
{
    /// <summary>
    /// PKCS #1 RSA OAEP: Encoding parameter specified
    /// </summary>
    public const ulong CKZ_DATA_SPECIFIED = 0x00000001;

    /// <summary>
    /// PKCS #5 PBKDF2 Key Generation: Salt specified
    /// </summary>
    public const ulong CKZ_SALT_SPECIFIED = 0x00000001;
}
