namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Type of slots to be obtained by PKCS#11 library
/// </summary>
public enum SlotsType
{
    /// <summary>
    /// Only slots with a token present
    /// </summary>
    WithTokenPresent,

    /// <summary>
    /// All slots regardless of token presence
    /// </summary>
    WithOrWithoutTokenPresent
}