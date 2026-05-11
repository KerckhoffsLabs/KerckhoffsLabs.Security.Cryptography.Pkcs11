using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Utility class that helps with logging
/// </summary>
public static class Pkcs11InteropLogUtils
{
    /// <summary>
    /// Converts CKU enum member to string that can be logged
    /// </summary>
    /// <param name="userType">CKU enum member</param>
    /// <returns>String value representing CKU enum member</returns>
    public static string ToString(CKU userType)
    {
        return userType switch
        {
            CKU.CKU_SO => "security officer",
            CKU.CKU_USER => "normal user",
            CKU.CKU_CONTEXT_SPECIFIC => "context specific user",
            _ => userType.ToString(),
        };
    }

    /// <summary>
    /// Converts SessionType enum member to string that can be logged
    /// </summary>
    /// <param name="sessionType">SessionType enum member</param>
    /// <returns>String value representing SessionType enum member</returns>
    public static string ToString(SessionType sessionType)
    {
        return sessionType switch
        {
            SessionType.ReadOnly => "read-only",
            SessionType.ReadWrite => "read-write",
            _ => (string)sessionType.ToString(),
        };
    }
}