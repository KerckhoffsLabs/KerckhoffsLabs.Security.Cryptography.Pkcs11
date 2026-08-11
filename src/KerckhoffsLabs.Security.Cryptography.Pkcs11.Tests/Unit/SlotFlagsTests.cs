using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SlotFlagsTests : FlagsContract<SlotFlags>
{
    protected override SlotFlags Make(ulong bits) => new(bits);
    protected override ulong RawValueOf(SlotFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<SlotFlags, bool> Get)[] All =>
    [
        (nameof(SlotFlags.TokenPresent), CKF.CKF_TOKEN_PRESENT, f => f.TokenPresent),
        (nameof(SlotFlags.RemovableDevice), CKF.CKF_REMOVABLE_DEVICE, f => f.RemovableDevice),
        (nameof(SlotFlags.HardwareSlot), CKF.CKF_HW_SLOT, f => f.HardwareSlot),
    ];
}
