using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Provides information about a token
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_TOKEN_INFO
{
    /// <summary>
    /// Application-defined label, assigned during token initialization. Must be padded with the blank character (' '). Should not be null-terminated.
    /// </summary>
    public CkChar32 Label;

    /// <summary>
    /// ID of the device manufacturer. Must be padded with the blank character (' '). Should not be nullterminated.
    /// </summary>
    public CkChar32 ManufacturerId;

    /// <summary>
    /// Model of the device. Must be padded with the blank character (' '). Should not be null-terminated.
    /// </summary>
    public CkChar16 Model;

    /// <summary>
    /// Character-string serial number of the device. Must be padded with the blank character (' '). Should not be null-terminated.
    /// </summary>
    public CkChar16 SerialNumber;

    /// <summary>
    /// Bit flags indicating capabilities and status of the device
    /// </summary>
    public NativeCULong Flags;

    /// <summary>
    /// Maximum number of sessions that can be opened with the token at one time by a single application
    /// </summary>
    public NativeCULong MaxSessionCount;

    /// <summary>
    /// Number of sessions that this application currently has open with the token
    /// </summary>
    public NativeCULong SessionCount;

    /// <summary>
    /// Maximum number of read/write sessions that can be opened with the token at one time by a single application
    /// </summary>
    public NativeCULong MaxRwSessionCount;

    /// <summary>
    /// Number of read/write sessions that this application currently has open with the token
    /// </summary>
    public NativeCULong RwSessionCount;

    /// <summary>
    /// Maximum length in bytes of the PIN
    /// </summary>
    public NativeCULong MaxPinLen;

    /// <summary>
    /// Minimum length in bytes of the PIN
    /// </summary>
    public NativeCULong MinPinLen;

    /// <summary>
    /// The total amount of memory on the token in bytes in which public objects may be stored
    /// </summary>
    public NativeCULong TotalPublicMemory;

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for public objects
    /// </summary>
    public NativeCULong FreePublicMemory;

    /// <summary>
    /// The total amount of memory on the token in bytes in which private objects may be stored
    /// </summary>
    public NativeCULong TotalPrivateMemory;

    /// <summary>
    /// The amount of free (unused) memory on the token in bytes for private objects
    /// </summary>
    public NativeCULong FreePrivateMemory;

    /// <summary>
    /// Version number of hardware
    /// </summary>
    public CK_VERSION HardwareVersion;

    /// <summary>
    /// Version number of firmware
    /// </summary>
    public CK_VERSION FirmwareVersion;

    /// <summary>
    /// Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx (4 characters for the year; 2 characters each for the month, the day, the hour, the minute, and the second; and 2 additional reserved '0' characters). The value of this field only makes sense for tokens equipped with a clock, as indicated in the token information flags.
    /// </summary>
    public CkChar16 UtcTime;
}
