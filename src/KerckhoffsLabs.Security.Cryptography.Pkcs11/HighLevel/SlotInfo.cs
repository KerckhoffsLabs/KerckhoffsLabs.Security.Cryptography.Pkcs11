using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Information about a slot
/// </summary>
public class SlotInfo
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
            return Convert.ToUInt64(_slotId);
        }
    }

    /// <summary>
    /// Description of the slot
    /// </summary>
    protected string? _slotDescription = null;

    /// <summary>
    /// Description of the slot
    /// </summary>
    public string? SlotDescription
    {
        get
        {
            return _slotDescription;
        }
    }

    /// <summary>
    /// ID of the slot manufacturer
    /// </summary>
    protected string? _manufacturerId = null;

    /// <summary>
    /// ID of the slot manufacturer
    /// </summary>
    public string? ManufacturerId
    {
        get
        {
            return _manufacturerId;
        }
    }

    /// <summary>
    /// Flags that provide capabilities of the slot
    /// </summary>
    protected SlotFlags? _slotFlags = null;

    /// <summary>
    /// Flags that provide capabilities of the slot
    /// </summary>
    public SlotFlags? SlotFlags
    {
        get
        {
            return _slotFlags;
        }
    }

    /// <summary>
    /// Version number of the slot's hardware
    /// </summary>
    protected string? _hardwareVersion = null;

    /// <summary>
    /// Version number of the slot's hardware
    /// </summary>
    public string? HardwareVersion
    {
        get
        {
            return _hardwareVersion;
        }
    }

    /// <summary>
    /// Version number of the slot's firmware
    /// </summary>
    protected string? _firmwareVersion = null;
    
    /// <summary>
    /// Version number of the slot's firmware
    /// </summary>
    public string? FirmwareVersion
    {
        get
        {
            return _firmwareVersion;
        }
    }

    /// <summary>
    /// Converts low level CK_SLOT_INFO structure to high level SlotInfo class
    /// </summary>
    /// <param name="slotId">PKCS#11 handle of slot</param>
    /// <param name="ck_slot_info">Low level CK_SLOT_INFO structure</param>
    protected internal SlotInfo(NativeCULong slotId, CK_SLOT_INFO ck_slot_info)
    {
        _slotId = slotId;
        _slotDescription = System.Text.Encoding.UTF8.GetString(ck_slot_info.SlotDescription).TrimEnd();
        _manufacturerId = System.Text.Encoding.UTF8.GetString(ck_slot_info.ManufacturerId).TrimEnd();
        _slotFlags = new SlotFlags(ck_slot_info.Flags);
        _hardwareVersion = ck_slot_info.HardwareVersion.ToString();
        _firmwareVersion = ck_slot_info.FirmwareVersion.ToString();
    }
}