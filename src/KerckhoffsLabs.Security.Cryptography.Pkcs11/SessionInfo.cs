using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A snapshot of a session's state, as reported by <c>C_GetSessionInfo</c>. Obtained from
/// <see cref="Pkcs11Workspace.GetSessionInfo"/>. The library is the only producer; instances are
/// not constructed by consumers.
/// </summary>
public sealed record SessionInfo
{
    /// <summary>PKCS#11 handle of session.</summary>
    public ulong SessionId { get; }

    /// <summary>PKCS#11 handle of slot that interfaces with the token.</summary>
    public ulong SlotId { get; }

    /// <summary>The state of the session.</summary>
    public CKS State { get; }

    /// <summary>Flags that define the type of session.</summary>
    public SessionFlags SessionFlags { get; }

    /// <summary>An error code defined by the cryptographic device used for errors not covered by Cryptoki.</summary>
    public ulong DeviceError { get; }

    internal SessionInfo(NativeCULong sessionId, CK_SESSION_INFO ck_session_info)
    {
        SessionId = (ulong)sessionId;
        SlotId = (ulong)ck_session_info.SlotId;
        State = (CKS)ck_session_info.State.Value;
        SessionFlags = new SessionFlags(ck_session_info.Flags);
        DeviceError = (ulong)ck_session_info.DeviceError;
    }
}
