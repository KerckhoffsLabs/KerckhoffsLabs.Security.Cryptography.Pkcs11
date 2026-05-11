namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Type of application that will be using PKCS#11 library
/// </summary>
public enum AppType
{
    /// <summary>
    /// Recommended option: PKCS#11 library will be used from multi-threaded application and needs to perform locking with native OS threading model (CKF_OS_LOCKING_OK)
    /// </summary>
    MultiThreaded,

    /// <summary>
    /// PKCS#11 library will be used from single-threaded application and does not need to perform any kind of locking
    /// </summary>
    SingleThreaded
}