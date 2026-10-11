namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Which structure a module receives as the <c>CKM_PKCS5_PBKD2</c> mechanism parameter; see
/// <see cref="Pkcs11LibraryOptions.Pbkdf2ParametersLayout"/>.
/// </summary>
/// <remarks>
/// <para>
/// The two structures differ only in <c>ulPasswordLen</c>. PKCS#11 v2.40 defined
/// <c>CK_PKCS5_PBKD2_PARAMS</c> with a <c>CK_ULONG_PTR</c> there, a defect that v2.40 Errata 01
/// corrected by adding <c>CK_PKCS5_PBKD2_PARAMS2</c>, which carries the length itself; v3.0 and later
/// specify only the corrected structure. On 64-bit Linux and macOS both are the same size, so a module
/// cannot tell from <c>ulParameterLen</c> which one it was given.
/// </para>
/// <para>
/// A wrong guess is not an error code. A module that reads the original structure dereferences the
/// length as an address and crashes the process; one that reads the corrected structure takes the
/// address as the length.
/// </para>
/// </remarks>
public enum Pbkdf2ParametersLayout
{
    /// <summary>
    /// <c>CK_PKCS5_PBKD2_PARAMS2</c>, except for a module known to read the original structure: Mozilla
    /// NSS softoken before 3.114, recognized from <c>C_GetSlotInfo</c> whether loaded directly or behind
    /// a proxy such as p11-kit's, or a module implementing a Cryptoki version before 2.40, from
    /// <c>C_GetInfo</c>. Decided once per slot, the first time the library derives a key with PBKDF2 there.
    /// </summary>
    Detect,

    /// <summary><c>CK_PKCS5_PBKD2_PARAMS2</c>: <c>ulPasswordLen</c> holds the password length.</summary>
    PasswordLengthByValue,

    /// <summary>
    /// <c>CK_PKCS5_PBKD2_PARAMS</c>: <c>ulPasswordLen</c> points at the password length, as the
    /// original v2.40 text defines it.
    /// </summary>
    PasswordLengthByReference,
}
