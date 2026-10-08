namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Types of Cryptoki users
/// </summary>
public enum CKU : ulong
{
    /// <summary>
    /// Security Officer
    /// </summary>
    CKU_SO = 0,

    /// <summary>
    /// Normal user
    /// </summary>
    CKU_USER = 1,

    /// <summary>
    /// Context specific
    /// </summary>
    CKU_CONTEXT_SPECIFIC = 2
}
