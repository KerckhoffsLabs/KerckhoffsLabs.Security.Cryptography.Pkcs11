namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Notifications
/// </summary>
public enum CKN : ulong
{
    /// <summary>
    /// Cryptoki is surrendering the execution of a function executing in a session so that the application may perform other operations
    /// </summary>
    CKN_SURRENDER = 0,

    /// <summary>
    /// Cryptoki is informing the application that the OTP for a key on a connected token just changed
    /// </summary>
    CKN_OTP_CHANGED = 1
}
