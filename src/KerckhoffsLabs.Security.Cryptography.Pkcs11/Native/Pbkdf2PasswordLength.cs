namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// How <c>CKM_PKCS5_PBKD2</c> passes <c>ulPasswordLen</c> to a module, as far as is known for the
/// whole module; see <see cref="LowLevelPkcs11Library.Pbkdf2PasswordLength"/>.
/// </summary>
internal enum Pbkdf2PasswordLength
{
    /// <summary>Not configured, and not yet detected.</summary>
    Undecided,

    /// <summary><c>CK_PKCS5_PBKD2_PARAMS2</c> on every slot.</summary>
    ByValue,

    /// <summary><c>CK_PKCS5_PBKD2_PARAMS</c> on every slot.</summary>
    ByReference,

    /// <summary>
    /// Decided slot by slot: the module did not identify itself as one whose layout is known, and may
    /// be a proxy such as p11-kit's, whose slots belong to different modules.
    /// </summary>
    PerSlot,
}
