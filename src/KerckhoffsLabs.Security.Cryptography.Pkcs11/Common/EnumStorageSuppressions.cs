// The spec enums in this namespace mirror PKCS#11 types declared as CK_ULONG, which is 64 bits wide on
// 64-bit Unix. Their storage is ulong so that every value a token returns — vendor-defined values
// included — is held exactly, instead of being truncated or overflowing on the way out. Int32 storage,
// which CA1028 and Sonar's S4022 recommend, cannot hold those values. Values going back to the token are
// narrowed in one place, which refuses one that does not fit this platform's CK_ULONG.
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum storage should be Int32",
    Justification = "PKCS#11 CK_ULONG values are 64 bits wide on 64-bit Unix; ulong storage keeps every token-returned value exact.",
    Scope = "namespaceanddescendants", Target = "~N:KerckhoffsLabs.Security.Cryptography.Pkcs11.Common")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S4022:Enumerations should have \"Int32\" storage",
    Justification = "PKCS#11 CK_ULONG values are 64 bits wide on 64-bit Unix; ulong storage keeps every token-returned value exact.",
    Scope = "namespaceanddescendants", Target = "~N:KerckhoffsLabs.Security.Cryptography.Pkcs11.Common")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S4022:Enumerations should have \"Int32\" storage",
    Justification = "CK_HKDF_PARAMS.ulSaltType is a CK_ULONG; see Common/EnumStorageSuppressions.cs.",
    Scope = "type", Target = "~T:KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams.HkdfSaltType")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum storage should be Int32",
    Justification = "CK_HKDF_PARAMS.ulSaltType is a CK_ULONG; see Common/EnumStorageSuppressions.cs.",
    Scope = "type", Target = "~T:KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams.HkdfSaltType")]
