using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags that provide capabilities of the slot.
/// </summary>
public sealed record SlotFlags
{
    /// <summary>Bit flags that provide capabilities of the slot.</summary>
    public ulong Flags { get; }

    /// <summary>True if a token is present in the slot (e.g. a device is in the reader).</summary>
    public bool TokenPresent
        => (Flags & CKF.CKF_TOKEN_PRESENT.Value) == CKF.CKF_TOKEN_PRESENT.Value;

    /// <summary>True if the reader supports removable devices.</summary>
    public bool RemovableDevice
        => (Flags & CKF.CKF_REMOVABLE_DEVICE.Value) == CKF.CKF_REMOVABLE_DEVICE.Value;

    /// <summary>True if the slot is a hardware slot, as opposed to a software slot implementing a "soft token".</summary>
    public bool HardwareSlot
        => (Flags & CKF.CKF_HW_SLOT.Value) == CKF.CKF_HW_SLOT.Value;

    internal SlotFlags(NativeCULong flags) => Flags = (ulong)flags;
}
