using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;

/// <summary>
/// A raw parameter block of a length <see cref="Mechanism"/> takes for a mechanism, for the cases that pass
/// one only to see what a policy or a check makes of a parameter it cannot read: the layout's size on this
/// platform where the mechanism has one, 16 bytes where it does not. The bytes are zeros.
/// </summary>
internal static class RawParameter
{
    internal static byte[] Of(CKM type)
        => new byte[MechanismParameterLength.For(type) is { } rule ? rule.Lengths.First(length => length > 0) : 16];
}
