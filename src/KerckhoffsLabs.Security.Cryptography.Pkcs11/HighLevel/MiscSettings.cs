using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Miscellaneous settings that operation of Pkcs11Interop library
/// </summary>
public static class MiscSettings
{
    /// <summary>
    /// Attributes that are known to contain nested attributes
    /// </summary>
    private static Dictionary<ulong, string> _attributesWithNestedAttributes = null;

    /// <summary>
    /// Attributes that are known to contain nested attributes
    /// </summary>
    public static Dictionary<ulong, string> AttributesWithNestedAttributes
    {
        get
        {
            return _attributesWithNestedAttributes;
        }
    }

    /// <summary>
    /// Initializes members of MiscSettings class
    /// </summary>
    static MiscSettings()
    {
        _attributesWithNestedAttributes = new Dictionary<ulong, string>
        {
            { (ulong)CKA.CKA_WRAP_TEMPLATE.ToCULong(), "CKA_WRAP_TEMPLATE" },
            { (ulong)CKA.CKA_UNWRAP_TEMPLATE.ToCULong(), "CKA_UNWRAP_TEMPLATE" },
            { (ulong)CKA.CKA_DERIVE_TEMPLATE.ToCULong(), "CKA_DERIVE_TEMPLATE" }
        };
    }
}
