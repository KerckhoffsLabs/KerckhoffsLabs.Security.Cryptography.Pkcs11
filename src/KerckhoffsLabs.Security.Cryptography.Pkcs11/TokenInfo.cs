using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Information about a token.
/// </summary>
public sealed record TokenInfo
{
    /// <summary>PKCS#11 handle of slot.</summary>
    public ulong SlotId { get; }

    /// <summary>Application-defined label, assigned during token initialization.</summary>
    public string Label { get; }

    /// <summary>ID of the device manufacturer.</summary>
    public string ManufacturerId { get; }

    /// <summary>Model of the device.</summary>
    public string Model { get; }

    /// <summary>Serial number of the device.</summary>
    public string SerialNumber { get; }

    /// <summary>Bit flags indicating capabilities and status of the device.</summary>
    public TokenFlags TokenFlags { get; }

    /// <summary>Maximum number of sessions that can be opened with the token at one time by a single application.</summary>
    public ulong MaxSessionCount { get; }

    /// <summary>Number of sessions that this application currently has open with the token.</summary>
    public ulong SessionCount { get; }

    /// <summary>Maximum number of read/write sessions that can be opened with the token at one time by a single application.</summary>
    public ulong MaxRwSessionCount { get; }

    /// <summary>Number of read/write sessions that this application currently has open with the token.</summary>
    public ulong RwSessionCount { get; }

    /// <summary>Maximum length in bytes of the PIN.</summary>
    public ulong MaxPinLen { get; }

    /// <summary>Minimum length in bytes of the PIN.</summary>
    public ulong MinPinLen { get; }

    /// <summary>The total amount of memory on the token in bytes in which public objects may be stored.</summary>
    public ulong TotalPublicMemory { get; }

    /// <summary>The amount of free (unused) memory on the token in bytes for public objects.</summary>
    public ulong FreePublicMemory { get; }

    /// <summary>The total amount of memory on the token in bytes in which private objects may be stored.</summary>
    public ulong TotalPrivateMemory { get; }

    /// <summary>The amount of free (unused) memory on the token in bytes for private objects.</summary>
    public ulong FreePrivateMemory { get; }

    /// <summary>Version number of hardware.</summary>
    public string HardwareVersion { get; }

    /// <summary>Version number of firmware.</summary>
    public string FirmwareVersion { get; }

    /// <summary>Current time (the value of this field only makes sense for tokens equipped with a clock).</summary>
    public string UtcTimeString { get; }

    /// <summary><see cref="UtcTimeString"/> converted to <see cref="DateTime"/>, or <c>null</c> if conversion failed.</summary>
    public DateTime? UtcTime { get; }

    internal TokenInfo(NativeCULong slotId, CK_TOKEN_INFO ck_token_info)
    {
        SlotId = (ulong)slotId;
        Label = Encoding.UTF8.GetString(ck_token_info.Label).TrimEnd();
        ManufacturerId = Encoding.UTF8.GetString(ck_token_info.ManufacturerId).TrimEnd();
        Model = Encoding.UTF8.GetString(ck_token_info.Model).TrimEnd();
        SerialNumber = Encoding.UTF8.GetString(ck_token_info.SerialNumber).TrimEnd();
        TokenFlags = new TokenFlags(ck_token_info.Flags);
        MaxSessionCount = (ulong)ck_token_info.MaxSessionCount;
        SessionCount = (ulong)ck_token_info.SessionCount;
        MaxRwSessionCount = (ulong)ck_token_info.MaxRwSessionCount;
        RwSessionCount = (ulong)ck_token_info.RwSessionCount;
        MaxPinLen = (ulong)ck_token_info.MaxPinLen;
        MinPinLen = (ulong)ck_token_info.MinPinLen;
        TotalPublicMemory = (ulong)ck_token_info.TotalPublicMemory;
        FreePublicMemory = (ulong)ck_token_info.FreePublicMemory;
        TotalPrivateMemory = (ulong)ck_token_info.TotalPrivateMemory;
        FreePrivateMemory = (ulong)ck_token_info.FreePrivateMemory;
        HardwareVersion = ck_token_info.HardwareVersion.ToString();
        FirmwareVersion = ck_token_info.FirmwareVersion.ToString();
        UtcTimeString = Encoding.UTF8.GetString(ck_token_info.UtcTime).TrimEnd();

        UtcTime = DateTime.TryParseExact(
            UtcTimeString,
            "yyyyMMddHHmmssff",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var parsedUtcTime)
                ? parsedUtcTime
                : null;
    }
}
