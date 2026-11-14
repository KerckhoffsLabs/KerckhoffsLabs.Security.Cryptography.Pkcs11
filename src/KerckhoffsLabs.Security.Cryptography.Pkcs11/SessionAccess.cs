namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Whether a session may change the token: a read-only or a read/write session (PKCS#11 v3.2,
/// <c>CKF_RW_SESSION</c> clear or set in <c>C_OpenSession</c>).
/// </summary>
/// <remarks>
/// <para>
/// A read-only session can still use keys, read objects and create session objects; what it cannot do is
/// create, change or destroy token objects. It is the least privilege, and the only kind a write-protected
/// token accepts.
/// </para>
/// <para>
/// The two exclude a Security Officer login: the SO cannot log in while the application has a read-only
/// session with the token, and no read-only session can be opened while the SO is logged in.
/// </para>
/// </remarks>
public enum SessionAccess
{
    /// <summary>A read-only session: <c>C_OpenSession</c> without <c>CKF_RW_SESSION</c>.</summary>
    ReadOnly,

    /// <summary>A read/write session: <c>C_OpenSession</c> with <c>CKF_RW_SESSION</c>.</summary>
    ReadWrite,
}
