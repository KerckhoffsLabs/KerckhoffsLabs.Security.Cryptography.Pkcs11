namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Trust-value identifiers for the CKA_TRUST_* attributes on <c>CKO_TRUST</c> objects
/// (PKCS#11 v3.2). Each value indicates the trust level for a specific usage.
/// </summary>
public enum CKT : uint
{
    /// <summary>Trust state is not known or has not been asserted.</summary>
    CKT_TRUST_UNKNOWN = 0x00000000,

    /// <summary>The associated certificate / key is trusted for the named usage.</summary>
    CKT_TRUSTED = 0x00000001,

    /// <summary>The associated certificate is a trust anchor (root).</summary>
    CKT_TRUST_ANCHOR = 0x00000002,

    /// <summary>The associated certificate / key is explicitly NOT trusted for the named usage.</summary>
    CKT_NOT_TRUSTED = 0x00000003,

    /// <summary>Trust must be re-verified at every use (no caching).</summary>
    CKT_TRUST_MUST_VERIFY_TRUST = 0x00000004,
}
