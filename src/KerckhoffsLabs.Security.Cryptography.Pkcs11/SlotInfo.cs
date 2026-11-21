using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Information about a slot.
/// </summary>
public sealed record SlotInfo
{
    /// <summary>Identifier of the slot this information describes.</summary>
    public SlotId SlotId { get; }

    /// <summary>Description of the slot.</summary>
    public string SlotDescription { get; }

    /// <summary>ID of the slot manufacturer.</summary>
    public string ManufacturerId { get; }

    /// <summary>Flags that provide capabilities of the slot.</summary>
    public SlotFlags SlotFlags { get; }

    /// <summary>Version number of the slot's hardware. See
    /// <see cref="LibraryInfo.CryptokiVersion"/> for how <c>CK_VERSION</c> encodes the minor field.</summary>
    public Version HardwareVersion { get; }

    /// <summary>Version number of the slot's firmware. See
    /// <see cref="LibraryInfo.CryptokiVersion"/> for how <c>CK_VERSION</c> encodes the minor field.</summary>
    public Version FirmwareVersion { get; }

    // The fields as the module reported them, padding removed (PaddedField.Raw), for comparisons.
    internal string RawSlotDescription { get; }
    internal string RawManufacturerId { get; }

    internal SlotInfo(NativeCULong slotId, CK_SLOT_INFO ck_slot_info)
    {
        SlotId = new SlotId((ulong)slotId);
        SlotDescription = Encoding.UTF8.GetString(ck_slot_info.SlotDescription).TrimEnd(' ', '\0');
        ManufacturerId = Encoding.UTF8.GetString(ck_slot_info.ManufacturerId).TrimEnd(' ', '\0');
        RawSlotDescription = Internal.PaddedField.Raw(ck_slot_info.SlotDescription);
        RawManufacturerId = Internal.PaddedField.Raw(ck_slot_info.ManufacturerId);
        SlotFlags = new SlotFlags((ulong)ck_slot_info.Flags);
        HardwareVersion = ck_slot_info.HardwareVersion.ToVersion();
        FirmwareVersion = ck_slot_info.FirmwareVersion.ToVersion();
    }
}
