using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags that provide capabilities of the slot
/// </summary>
public class SlotFlags
{
    /// <summary>
    /// Bits flags that provide capabilities of the slot
    /// </summary>
    protected NativeCULong _flags;

    /// <summary>
    /// Bits flags that provide capabilities of the slot
    /// </summary>
    public ulong Flags
    {
        get
        {
            return (ulong)_flags;
        }
    }

    /// <summary>
    /// True if a token is present in the slot (e.g. a device is in the reader)
    /// </summary>
    public bool TokenPresent
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_TOKEN_PRESENT.Value).Value == CKF.CKF_TOKEN_PRESENT.Value;
        }
    }

    /// <summary>
    /// True if the reader supports removable devices
    /// </summary>
    public bool RemovableDevice
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_REMOVABLE_DEVICE.Value).Value == CKF.CKF_REMOVABLE_DEVICE.Value;
        }
    }

    /// <summary>
    /// True if the slot is a hardware slot, as opposed to a software slot implementing a "soft token"
    /// </summary>
    public bool HardwareSlot
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_HW_SLOT.Value).Value == CKF.CKF_HW_SLOT.Value;
        }
    }

    /// <summary>
    /// Initializes new instance of SlotFlags class
    /// </summary>
    /// <param name="flags">Bits flags that provide capabilities of the slot</param>
    protected internal SlotFlags(NativeCULong flags)
    {
        _flags = flags;
    }
}