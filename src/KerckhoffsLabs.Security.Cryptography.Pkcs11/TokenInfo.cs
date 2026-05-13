using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Information about a token
/// </summary>
public class TokenInfo
{
    /// <summary>
    /// PKCS#11 handle of slot
    /// </summary>
    protected NativeCULong _slotId = CK.CK_INVALID_HANDLE;

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
    /// Application-defined label, assigned during token initialization
    /// </summary>
    protected string? _label = null;

    /// <summary>
    /// Application-defined label, assigned during token initialization
    /// </summary>
    public string? Label
    {
        get
        {
            return _label;
        }
    }

    /// <summary>
    /// ID of the device manufacturer
    /// </summary>
    protected string? _manufacturerId = null;

    /// <summary>
    /// ID of the device manufacturer
    /// </summary>
    public string? ManufacturerId
    {
        get
        {
            return _manufacturerId;
        }
    }

    /// <summary>
    /// Model of the device
    /// </summary>
    protected string? _model = null;

    /// <summary>
    /// Model of the device
    /// </summary>
    public string? Model
    {
        get
        {
            return _model;
        }
    }

    /// <summary>
    /// Serial number of the device
    /// </summary>
    protected string? _serialNumber = null;

    /// <summary>
    /// Serial number of the device
    /// </summary>
    public string? SerialNumber
    {
        get
        {
            return _serialNumber;
        }
    }

    /// <summary>
    /// Bit flags indicating capabilities and status of the device
    /// </summary>
    protected TokenFlags? _tokenFlags = null;

    /// <summary>
    /// Bit flags indicating capabilities and status of the device
    /// </summary>
    public TokenFlags? TokenFlags
    {
        get
        {
            return _tokenFlags;
        }
    }

    /// <summary>
    /// Maximum number of sessions that can be opened with the token at one time by a single application
    /// </summary>
    protected NativeCULong _maxSessionCount = new (0);

    /// <summary>
    /// Maximum number of sessions that can be opened with the token at one time by a single application
    /// </summary>
    public ulong MaxSessionCount
    {
        get
        {
            return (ulong)_maxSessionCount;
        }
    }

    /// <summary>
    /// Number of sessions that this application currently has open with the token
    /// </summary>
    protected NativeCULong _sessionCount = new(0);

    /// <summary>
    /// Number of sessions that this application currently has open with the token
    /// </summary>
    public ulong SessionCount
    {
        get
        {
            return (ulong)_sessionCount;
        }
    }

    /// <summary>
    /// Maximum number of read/write sessions that can be opened with the token at one time by a single application
    /// </summary>
    protected NativeCULong _maxRwSessionCount = new (0);

    /// <summary>
    /// Maximum number of read/write sessions that can be opened with the token at one time by a single application
    /// </summary>
    public ulong MaxRwSessionCount
    {
        get
        {
            return (ulong)_maxRwSessionCount;
        }
    }

    /// <summary>
    /// Number of read/write sessions that this application currently has open with the token
    /// </summary>
    protected NativeCULong _rwSessionCount = new (0);

    /// <summary>
    /// Number of read/write sessions that this application currently has open with the token
    /// </summary>
    public ulong RwSessionCount
    {
        get
        {
            return (ulong)_rwSessionCount;
        }
    }

    /// <summary>
    /// Maximum length in bytes of the PIN
    /// </summary>
    protected NativeCULong _maxPinLen = new (0);

    /// <summary>
    /// Maximum length in bytes of the PIN
    /// </summary>
    public ulong MaxPinLen
    {
        get
        {
            return (ulong)_maxPinLen;
        }
    }

    /// <summary>
    /// Minimum length in bytes of the PIN
    /// </summary>
    protected NativeCULong _minPinLen = new (0);

    /// <summary>
    /// Minimum length in bytes of the PIN
    /// </summary>
    public ulong MinPinLen
    {
        get
        {
            return (ulong)_minPinLen;
        }
    }

    /// <summary>
    /// The total amount of memory on the token in bytes in which public objects may be stored
    /// </summary>
    protected NativeCULong _totalPublicMemory = new (0);

    /// <summary>
    /// The total amount of memory on the token in bytes in which public objects may be stored
    /// </summary>
    public ulong TotalPublicMemory
    {
        get
        {
            return (ulong)_totalPublicMemory;
        }
    }

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for public objects
    /// </summary>
    protected NativeCULong _freePublicMemory = new (0);

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for public objects
    /// </summary>
    public ulong FreePublicMemory
    {
        get
        {
            return (ulong)_freePublicMemory;
        }
    }

    /// <summary>
    /// The total amount of memory on the token in bytes in which private objects may be stored
    /// </summary>
    protected NativeCULong _totalPrivateMemory = new (0);

    /// <summary>
    /// The total amount of memory on the token in bytes in which private objects may be stored
    /// </summary>
    public ulong TotalPrivateMemory
    {
        get
        {
            return (ulong)_totalPrivateMemory;
        }
    }

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for private objects
    /// </summary>
    protected NativeCULong _freePrivateMemory = new (0);

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for private objects
    /// </summary>
    public ulong FreePrivateMemory
    {
        get
        {
            return (ulong)_freePrivateMemory;
        }
    }

    /// <summary>
    /// Version number of hardware
    /// </summary>
    protected string? _hardwareVersion = null;

    /// <summary>
    /// Version number of hardware
    /// </summary>
    public string? HardwareVersion
    {
        get
        {
            return _hardwareVersion;
        }
    }

    /// <summary>
    /// Version number of firmware
    /// </summary>
    protected string? _firmwareVersion = null;

    /// <summary>
    /// Version number of firmware
    /// </summary>
    public string? FirmwareVersion
    {
        get
        {
            return _firmwareVersion;
        }
    }

    /// <summary>
    /// Current time (the value of this field only makes sense for tokens equipped with a clock)
    /// </summary>
    protected string? _utcTimeString = null;

    /// <summary>
    /// Current time (the value of this field only makes sense for tokens equipped with a clock)
    /// </summary>
    public string? UtcTimeString
    {
        get
        {
            return _utcTimeString;
        }
    }

    /// <summary>
    /// UtcTimeString converted to DateTime or null if conversion failed
    /// </summary>
    protected DateTime? _utcTime = null;

    /// <summary>
    /// UtcTimeString converted to DateTime or null if conversion failed
    /// </summary>
    public DateTime? UtcTime
    {
        get
        {
            return _utcTime;
        }
    }

    /// <summary>
    /// Converts low level CK_TOKEN_INFO structure to high level TokenInfo class
    /// </summary>
    /// <param name="slotId">PKCS#11 handle of slot</param>
    /// <param name="ck_token_info">Low level CK_TOKEN_INFO structure</param>
    protected internal TokenInfo(NativeCULong slotId, CK_TOKEN_INFO ck_token_info)
    {
        _slotId = slotId;
        _label = System.Text.Encoding.UTF8.GetString(ck_token_info.Label).TrimEnd();
        _manufacturerId = System.Text.Encoding.UTF8.GetString(ck_token_info.ManufacturerId).TrimEnd();
        _model = System.Text.Encoding.UTF8.GetString(ck_token_info.Model).TrimEnd();
        _serialNumber = System.Text.Encoding.UTF8.GetString(ck_token_info.SerialNumber).TrimEnd();
        _tokenFlags = new TokenFlags(ck_token_info.Flags);
        _maxSessionCount = ck_token_info.MaxSessionCount;
        _sessionCount = ck_token_info.SessionCount;
        _maxRwSessionCount = ck_token_info.MaxRwSessionCount;
        _rwSessionCount = ck_token_info.RwSessionCount;
        _maxPinLen = ck_token_info.MaxPinLen;
        _minPinLen = ck_token_info.MinPinLen;
        _totalPublicMemory = ck_token_info.TotalPublicMemory;
        _freePublicMemory = ck_token_info.FreePublicMemory;
        _totalPrivateMemory = ck_token_info.TotalPrivateMemory;
        _freePrivateMemory = ck_token_info.FreePrivateMemory;
        _hardwareVersion = ck_token_info.HardwareVersion.ToString();
        _firmwareVersion = ck_token_info.FirmwareVersion.ToString();
        _utcTimeString = System.Text.Encoding.UTF8.GetString(ck_token_info.UtcTime).TrimEnd();

        _utcTime = DateTime.TryParseExact(
            _utcTimeString,
            "yyyyMMddHHmmssff",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var _parsedUtcTime)
                ? _parsedUtcTime
                : (DateTime?)null;
    }
}