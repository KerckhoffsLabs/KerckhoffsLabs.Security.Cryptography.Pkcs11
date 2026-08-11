using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags that define the type of session.
/// </summary>
public sealed record SessionFlags
{
    /// <summary>Bit flags that define the type of session.</summary>
    public ulong Flags { get; }

    /// <summary>True if the session is read/write; false if the session is read-only.</summary>
    public bool RwSession
        => (Flags & CKF.CKF_RW_SESSION) == CKF.CKF_RW_SESSION;

    /// <summary>This flag is provided for backward compatibility, and should always be set to true.</summary>
    public bool SerialSession
        => (Flags & CKF.CKF_SERIAL_SESSION) == CKF.CKF_SERIAL_SESSION;

    internal SessionFlags(ulong flags) => Flags = flags;
}
