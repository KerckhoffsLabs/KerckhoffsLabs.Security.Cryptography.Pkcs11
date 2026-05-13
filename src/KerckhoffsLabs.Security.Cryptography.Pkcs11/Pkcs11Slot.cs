using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Logical reader that potentially contains a token
/// </summary>
public class Pkcs11Slot
{
    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Slot>();

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    protected LowLevelPkcs11Library _pkcs11Library = null;

    /// <summary>
    /// PKCS#11 handle of slot
    /// </summary>
    protected NativeCULong _slotId = new (0);

    /// <summary>
    /// PKCS#11 handle of slot
    /// </summary>
    public ulong SlotId
    {
        get
        {
            return (ulong)_slotId;
        }
    }

    /// <summary>
    /// Initializes new instance of Pkcs11Slot class
    /// </summary>
    /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
    /// <param name="slotId">PKCS#11 handle of slot</param>
    protected internal Pkcs11Slot(LowLevelPkcs11Library pkcs11Library, ulong slotId)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::ctor", slotId);

        if (pkcs11Library == null)
            throw new ArgumentNullException("pkcs11Library");

        _pkcs11Library = pkcs11Library;
        _slotId = (NativeCULong)(slotId);
        }

    /// <summary>
    /// Obtains information about a particular slot in the system
    /// </summary>
    /// <returns>Slot information</returns>
    public SlotInfo GetSlotInfo()
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::GetSlotInfo", _slotId);

        CK_SLOT_INFO slotInfo = new();
        CKR rv = _pkcs11Library.C_GetSlotInfo(_slotId, ref slotInfo);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSlotInfo");

        return new SlotInfo(_slotId, slotInfo);
    }

    /// <summary>
    /// Obtains information about a particular token in the system.
    /// </summary>
    /// <returns>Token information</returns>
    public TokenInfo GetTokenInfo()
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::GetTokenInfo", _slotId);

        CK_TOKEN_INFO tokenInfo = new();
        CKR rv = _pkcs11Library.C_GetTokenInfo(_slotId, ref tokenInfo);
        Pkcs11Exception.ThrowIfError(rv, "C_GetTokenInfo");

        return new TokenInfo(_slotId, tokenInfo);
    }

    /// <summary>
    /// Obtains a list of mechanism types supported by a token
    /// </summary>
    /// <returns>List of mechanism types supported by a token</returns>
    public List<CKM> GetMechanismList()
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::GetMechanismList", _slotId);

        NativeCULong mechanismCount = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetMechanismList(_slotId, null, ref mechanismCount);
        Pkcs11Exception.ThrowIfError(rv, "C_GetMechanismList");

        if (mechanismCount < (NativeCULong)1)
            return new List<CKM>();

        CKM[] mechanismList = new CKM[(int)mechanismCount];
        rv = _pkcs11Library.C_GetMechanismList(_slotId, mechanismList, ref mechanismCount);
        Pkcs11Exception.ThrowIfError(rv, "C_GetMechanismList");

        if (mechanismList.Length != (int)(mechanismCount))
            Array.Resize(ref mechanismList, (int)(mechanismCount));

        return new List<CKM>(mechanismList);
    }

    /// <summary>
    /// Obtains information about a particular mechanism possibly supported by a token
    /// </summary>
    /// <param name="mechanism">Mechanism</param>
    /// <returns>Information about mechanism</returns>
    public MechanismInfo GetMechanismInfo(CKM mechanism)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::GetMechanismInfo", _slotId);

        CK_MECHANISM_INFO mechanismInfo = new CK_MECHANISM_INFO();
        CKR rv = _pkcs11Library.C_GetMechanismInfo(_slotId, mechanism, ref mechanismInfo);
        Pkcs11Exception.ThrowIfError(rv, "C_GetMechanismInfo");

        return new MechanismInfo(mechanism, mechanismInfo);
    }

    /// <summary>
    /// Initializes a token
    /// </summary>
    /// <param name="soPin">SO's initial PIN</param>
    /// <param name="label">Label of the token</param>
    public void InitToken(string soPin, string label)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::InitToken1", _slotId);

        byte[] soPinValue = null;
        NativeCULong soPinValueLen = (NativeCULong)0;
        if (soPin != null)
        {
            soPinValue = System.Text.Encoding.UTF8.GetBytes(soPin);
            soPinValueLen = (NativeCULong)(soPinValue.Length);
        }

        byte[] tokenLabel = new byte[32];
        Array.Fill(tokenLabel, (byte)0x20);
        if (label != null) { byte[] _lb = System.Text.Encoding.UTF8.GetBytes(label); Array.Copy(_lb, 0, tokenLabel, 0, Math.Min(_lb.Length, 32)); }

        CKR rv = _pkcs11Library.C_InitToken(_slotId, soPinValue, soPinValueLen, tokenLabel);
        Pkcs11Exception.ThrowIfError(rv, "C_InitToken");
    }

    /// <summary>
    /// Initializes a token
    /// </summary>
    /// <param name="soPin">SO's initial PIN</param>
    /// <param name="label">Label of the token</param>
    public void InitToken(byte[] soPin, byte[] label)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::InitToken2", _slotId);

        byte[] soPinValue = null;
        NativeCULong soPinValueLen = (NativeCULong)0;
        if (soPin != null)
        {
            soPinValue = soPin;
            soPinValueLen = (NativeCULong)(soPin.Length);
        }

        // PKCS#11 v2.20 page 113:
        // pLabel points to the 32-byte label of the token (which must be padded with
        // blank characters, and which must not be null-terminated).
        byte[] tokenLabel = new byte[32];
        for (int i = 0; i < tokenLabel.Length; i++)
            tokenLabel[i] = 0x20;

        if (label != null)
        {
            if (label.Length > 32)
                throw new Exception("Label too long");
            Array.Copy(label, 0, tokenLabel, 0, label.Length);
        }

        CKR rv = _pkcs11Library.C_InitToken(_slotId, soPinValue, soPinValueLen, tokenLabel);
        Pkcs11Exception.ThrowIfError(rv, "C_InitToken");
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot
    /// </summary>
    /// <param name="sessionType">Type of session to be opened</param>
    /// <returns>Session</returns>
    public Session OpenSession(SessionType sessionType)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::OpenSession", _slotId);

        NativeCULong flags = CKF.CKF_SERIAL_SESSION;
        if (sessionType == SessionType.ReadWrite)
            flags = flags | CKF.CKF_RW_SESSION;

        NativeCULong sessionId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_OpenSession(_slotId, flags, IntPtr.Zero, IntPtr.Zero, ref sessionId);
        Pkcs11Exception.ThrowIfError(rv, "C_OpenSession");

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Opened {SessionType} session {SessionId} with token in slot {SlotId}", Pkcs11LogUtils.ToString(sessionType), sessionId, _slotId);

        return new Session(_pkcs11Library, (ulong)sessionId);
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    /// <param name="session">Session</param>
    public void CloseSession(Session session)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::CloseSession", _slotId);

        if (session == null)
            throw new ArgumentNullException("session");

        session.CloseSession();
    }

    /// <summary>
    /// Closes all sessions an application has with a token
    /// </summary>
    public void CloseAllSessions()
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::CloseAllSessions", _slotId);

        _logger.LogInformation("Closing all sessions with token in slot {SlotId}", _slotId);

        CKR rv = _pkcs11Library.C_CloseAllSessions(_slotId);
        Pkcs11Exception.ThrowIfError(rv, "C_CloseAllSessions");
    }
}
