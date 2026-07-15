using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Helpers that turn PKCS#11 enum values into human-friendly strings suitable
/// for log messages. Used only at log-site formatting — does not allocate.
/// </summary>
internal static class Pkcs11LogUtils
{
    /// <summary>
    /// Converts a <see cref="CKU"/> user-type enum value to a short label
    /// (<c>"security officer"</c>, <c>"normal user"</c>, etc.).
    /// </summary>
    public static string ToString(CKU userType) => userType switch
    {
        CKU.CKU_SO => "security officer",
        CKU.CKU_USER => "normal user",
        CKU.CKU_CONTEXT_SPECIFIC => "context specific user",
        _ => userType.ToString(),
    };
}
