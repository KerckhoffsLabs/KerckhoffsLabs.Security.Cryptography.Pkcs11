using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Information about a slot.
/// </summary>
public sealed record SlotInfo
{
    /// <summary>PKCS#11 handle of slot.</summary>
    public ulong SlotId { get; }

    /// <summary>Description of the slot.</summary>
    public string SlotDescription { get; }

    /// <summary>ID of the slot manufacturer.</summary>
    public string ManufacturerId { get; }

    /// <summary>Flags that provide capabilities of the slot.</summary>
    public SlotFlags SlotFlags { get; }

    /// <summary>Version number of the slot's hardware.</summary>
    public string HardwareVersion { get; }

    /// <summary>Version number of the slot's firmware.</summary>
    public string FirmwareVersion { get; }

    internal SlotInfo(NativeCULong slotId, CK_SLOT_INFO ck_slot_info)
    {
        SlotId = (ulong)slotId;
        SlotDescription = Encoding.UTF8.GetString(ck_slot_info.SlotDescription).TrimEnd();
        ManufacturerId = Encoding.UTF8.GetString(ck_slot_info.ManufacturerId).TrimEnd();
        SlotFlags = new SlotFlags(ck_slot_info.Flags);
        HardwareVersion = ck_slot_info.HardwareVersion.ToString();
        FirmwareVersion = ck_slot_info.FirmwareVersion.ToString();
    }
}
