namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Who logs in to a token: the normal user or the Security Officer (PKCS#11 v3.2, <c>CKU_USER</c> and
/// <c>CKU_SO</c>).
/// </summary>
/// <remarks>
/// <para>
/// A login belongs to the token and the application, not to a session: every session the application has
/// with the token shares it (v3.2 §5.6, "Session management functions"). So only one of these can be logged
/// in at a time, and logging in as the other one while it is fails with
/// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>.
/// </para>
/// <para>
/// There is deliberately no value for <c>CKU_CONTEXT_SPECIFIC</c>: that is never a token login but the
/// re-authentication a key with <c>CKA_ALWAYS_AUTHENTICATE</c> needs inside one operation, which the library
/// performs itself.
/// </para>
/// </remarks>
public enum TokenUser
{
    /// <summary>
    /// The normal user (<c>CKU_USER</c>), who uses the token's private objects and keys. The usual choice for
    /// an application.
    /// </summary>
    User,

    /// <summary>
    /// The Security Officer (<c>CKU_SO</c>), who initializes the token and the normal user's PIN, and cannot
    /// use private objects. While the SO is logged in, the application can hold only read/write sessions with
    /// the token.
    /// </summary>
    SecurityOfficer,
}
