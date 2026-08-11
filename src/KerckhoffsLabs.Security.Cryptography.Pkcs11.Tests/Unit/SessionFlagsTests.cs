using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class SessionFlagsTests : FlagsContract<SessionFlags>
{
    protected override SessionFlags Make(ulong bits) => new(bits);
    protected override ulong RawValueOf(SessionFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<SessionFlags, bool> Get)[] All =>
    [
        (nameof(SessionFlags.RwSession), CKF.CKF_RW_SESSION, f => f.RwSession),
        (nameof(SessionFlags.SerialSession), CKF.CKF_SERIAL_SESSION, f => f.SerialSession),
    ];
}
