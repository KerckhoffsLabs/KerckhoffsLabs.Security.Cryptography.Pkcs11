namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Which HKDF steps to perform (PKCS#11 v3.0 <c>CK_HKDF_PARAMS</c> <c>bExtract</c>/<c>bExpand</c>).
/// </summary>
/// <remarks>
/// The native struct carries these as two independent booleans, but at least one step is
/// required — both false requests neither step, which no token can execute. This type
/// removes that illegal fourth combination from the API.
/// </remarks>
public enum HkdfOperation
{
    /// <summary>HKDF-Extract only: derive a pseudorandom key (PRK) from input keying material and salt.</summary>
    ExtractOnly,

    /// <summary>HKDF-Expand only: the base key is used directly as the PRK.</summary>
    ExpandOnly,

    /// <summary>HKDF-Extract followed by HKDF-Expand — the common case.</summary>
    ExtractAndExpand,
}
