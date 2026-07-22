using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// CK_INFO.flags defines no bits today (the PKCS#11 spec reserves it, always zero), so unlike its
// sibling flag records this one has nothing to decode — All is empty and the shared contract only
// exercises the raw-value round-trip and record equality it still needs to get right.
public sealed class LibraryFlagsTests : FlagsContract<LibraryFlags>
{
    protected override LibraryFlags Make(ulong bits) => new((NativeCULong)bits);
    protected override ulong RawValueOf(LibraryFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<LibraryFlags, bool> Get)[] All => [];
}
