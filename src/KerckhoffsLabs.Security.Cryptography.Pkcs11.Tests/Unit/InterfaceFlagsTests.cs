using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class InterfaceFlagsTests : FlagsContract<InterfaceFlags>
{
    protected override InterfaceFlags Make(ulong bits) => new((NativeCULong)bits);
    protected override ulong RawValueOf(InterfaceFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<InterfaceFlags, bool> Get)[] All =>
    [
        (nameof(InterfaceFlags.ForkSafe), CKF.CKF_INTERFACE_FORK_SAFE.Value, f => f.ForkSafe),
    ];
}
