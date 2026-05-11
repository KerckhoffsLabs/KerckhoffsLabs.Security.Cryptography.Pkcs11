namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

 /// <summary>
/// Source of PKCS#11 function pointers
/// </summary>
public enum InitType
{
    /// <summary>
    /// Recommended option: PKCS#11 function pointers will be acquired with single call of C_GetFunctionList function
    /// </summary>
    WithFunctionList,

    /// <summary>
    /// PKCS#11 function pointers will be acquired with multiple calls of GetProcAddress or dlsym function
    /// </summary>
    WithoutFunctionList
}