using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Provides information about a slot
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_SLOT_INFO
{
    /// <summary>
    /// Character-string description of the slot. Must be padded with the blank character (‘ ‘). Should not be null-terminated.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] SlotDescription;

    /// <summary>
    /// ID of the slot manufacturer. Must be padded with the blank character (‘ ‘). Should not be null-terminated.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] ManufacturerId;

    /// <summary>
    /// Bits flags that provide capabilities of the slot.
    /// </summary>
    public NativeCULong Flags;

    /// <summary>
    /// Version number of the slot's hardware
    /// </summary>
    public CK_VERSION HardwareVersion;

    /// <summary>
    /// Version number of the slot's firmware
    /// </summary>
    public CK_VERSION FirmwareVersion;
}