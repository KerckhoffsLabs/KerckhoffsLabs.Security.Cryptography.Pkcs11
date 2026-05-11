using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Information about a session
/// </summary>
public class SessionInfo
{
    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    protected NativeCULong _sessionId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    public ulong SessionId
    {
        get
        {
            return Convert.ToUInt64(_sessionId);
        }
    }

    /// <summary>
    /// PKCS#11 handle of slot that interfaces with the token
    /// </summary>
    protected NativeCULong _slotId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of slot that interfaces with the token
    /// </summary>
    public ulong SlotId
    {
        get
        {
            return Convert.ToUInt64(_slotId);
        }
    }

    /// <summary>
    /// The state of the session
    /// </summary>
    protected CKS _state = 0;

    /// <summary>
    /// The state of the session
    /// </summary>
    public CKS State
    {
        get
        {
            return _state;
        }
    }

    /// <summary>
    /// Flags that define the type of session
    /// </summary>
    protected SessionFlags _sessionFlags = null;

    /// <summary>
    /// Flags that define the type of session
    /// </summary>
    public SessionFlags SessionFlags
    {
        get
        {
            return _sessionFlags;
        }
    }

    /// <summary>
    /// An error code defined by the cryptographic device used for errors not covered by Cryptoki
    /// </summary>
    protected NativeCULong _deviceError = new (0);

    /// <summary>
    /// An error code defined by the cryptographic device used for errors not covered by Cryptoki
    /// </summary>
    public ulong DeviceError
    {
        get
        {
            return Convert.ToUInt64(_deviceError);
        }
    }

    /// <summary>
    /// Converts low level CK_SESSION_INFO structure to high level SessionInfo class
    /// </summary>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    /// <param name="ck_session_info">Low level CK_SESSION_INFO structure</param>
    protected internal SessionInfo(NativeCULong sessionId, CK_SESSION_INFO ck_session_info)
    {
        _sessionId = sessionId;
        _slotId = ck_session_info.SlotId;
        _state = (CKS)ck_session_info.State.Value;
        _sessionFlags = new SessionFlags(ck_session_info.Flags);
        _deviceError = ck_session_info.DeviceError;
    }
}