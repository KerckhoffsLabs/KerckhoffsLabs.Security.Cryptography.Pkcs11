using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Provides information about a particular mechanism.
/// </summary>
public sealed record MechanismInfo
{
    /// <summary>Mechanism.</summary>
    public CKM Mechanism { get; }

    /// <summary>The minimum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent).</summary>
    public ulong MinKeySize { get; }

    /// <summary>The maximum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent).</summary>
    public ulong MaxKeySize { get; }

    /// <summary>Flags specifying mechanism capabilities.</summary>
    public MechanismFlags MechanismFlags { get; }

    internal MechanismInfo(CKM mechanism, CK_MECHANISM_INFO ck_mechanism_info)
    {
        Mechanism = mechanism;
        MinKeySize = (ulong)ck_mechanism_info.MinKeySize;
        MaxKeySize = (ulong)ck_mechanism_info.MaxKeySize;
        MechanismFlags = new MechanismFlags(ck_mechanism_info.Flags);
    }
}
