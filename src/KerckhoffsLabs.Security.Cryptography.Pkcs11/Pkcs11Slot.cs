using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Logical reader that potentially contains a token
/// </summary>
public sealed class Pkcs11Slot
{
    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Slot>();

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private LowLevelPkcs11Library _pkcs11Library = null;

    /// <summary>
    /// PKCS#11 handle of slot
    /// </summary>
    private NativeCULong _slotId = new (0);

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
    internal Pkcs11Slot(LowLevelPkcs11Library pkcs11Library, ulong slotId)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::ctor", slotId);

        ArgumentNullException.ThrowIfNull(pkcs11Library);

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
    /// Initializes the token in this slot with the Security Officer PIN and a
    /// human-readable label. After this call the token is in its factory state —
    /// any prior keys, certificates, or user PIN are destroyed.
    /// </summary>
    /// <param name="soPin">Security Officer's initial PIN. Caller retains
    /// ownership of the <see cref="SecurePin"/>; this method copies into a
    /// transient buffer and zeroes it after the native call returns.</param>
    /// <param name="label">Token label. Encoded as UTF-8; must encode to 32
    /// bytes or fewer. PKCS#11 pads the label with ASCII spaces (0x20) to fill
    /// the on-token 32-byte field; it must NOT be null-terminated.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="soPin"/>
    /// or <paramref name="label"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="label"/>
    /// encodes to more than 32 bytes of UTF-8.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying
    /// <c>C_InitToken</c> call.</exception>
    public void InitToken(SecurePin soPin, string label)
    {
        ArgumentNullException.ThrowIfNull(soPin);
        ArgumentNullException.ThrowIfNull(label);

        _logger.LogDebug("Pkcs11Slot({SlotId})::InitToken", _slotId);

        // PKCS#11 v3.1 §11.5: pLabel points to a 32-byte field padded with
        // ASCII spaces (0x20) and must not be null-terminated.
        byte[] labelBytes = System.Text.Encoding.UTF8.GetBytes(label);
        if (labelBytes.Length > 32)
            throw new ArgumentException(
                $"Token label must encode to 32 UTF-8 bytes or fewer (got {labelBytes.Length}).",
                nameof(label));
        byte[] tokenLabel = new byte[32];
        Array.Fill(tokenLabel, (byte)0x20);
        Array.Copy(labelBytes, 0, tokenLabel, 0, labelBytes.Length);

        // Copy the SecurePin into a transient buffer for the native call and
        // zero it on the way out. Matches Pkcs11Session.Login's pattern.
        byte[] pinBuffer = soPin.Pin.ToArray();
        try
        {
            CKR rv = _pkcs11Library.C_InitToken(
                _slotId, pinBuffer, (NativeCULong)pinBuffer.Length, tokenLabel);
            Pkcs11Exception.ThrowIfError(rv, "C_InitToken");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBuffer);
        }
    }

    /// <summary>
    /// Opens a session between an application and a token in a particular slot.
    /// </summary>
    /// <param name="readWrite">
    /// When <c>true</c> (the default), opens a read-write session
    /// (<c>CKF_SERIAL_SESSION | CKF_RW_SESSION</c>). When <c>false</c>, opens a
    /// read-only session — token-object creation will fail per PKCS#11 spec.
    /// </param>
    /// <returns>The opened session.</returns>
    internal Pkcs11Session OpenSession(bool readWrite = true)
    {
        _logger.LogDebug("Pkcs11Slot({SlotId})::OpenSession", _slotId);

        NativeCULong flags = CKF.CKF_SERIAL_SESSION;
        if (readWrite)
            flags = flags | CKF.CKF_RW_SESSION;

        NativeCULong sessionId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_OpenSession(_slotId, flags, IntPtr.Zero, IntPtr.Zero, ref sessionId);
        Pkcs11Exception.ThrowIfError(rv, "C_OpenSession");

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation(
                "Opened {SessionType} session {SessionId} with token in slot {SlotId}",
                readWrite ? "read-write" : "read-only", sessionId, _slotId);

        return new Pkcs11Session(_pkcs11Library, (ulong)sessionId);
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
