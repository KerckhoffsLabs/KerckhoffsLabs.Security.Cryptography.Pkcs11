namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Bit flags reserved for future versions of Cryptoki. The PKCS#11 spec defines no bits here today —
/// <c>CK_INFO.flags</c> must be zero — but the field is versioned the same way <see cref="TokenFlags"/>
/// picked up <c>CKF_SEED_RANDOM_REQUIRED</c> in v3.0, so it's wrapped for parity rather than left as a
/// bare integer.
/// </summary>
public sealed record LibraryFlags
{
    /// <summary>Bit flags reserved for future versions.</summary>
    public ulong Flags { get; }

    internal LibraryFlags(ulong flags) => Flags = flags;
}
