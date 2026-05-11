namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Exception with the name of PKCS#11 method that failed and its return value
/// </summary>
/// <remarks>
/// Initializes new instance of Pkcs11Exception class
/// </remarks>
/// <param name="method">Name of method that caused exception</param>
/// <param name="rv">Return value of method that caused exception</param>
public class Pkcs11Exception(string method, CKR rv) : Exception(string.Format("Method {0} returned {1}", method, rv.ToString()))
{
    /// <summary>
    /// Name of method that caused exception
    /// </summary>
    private readonly string _method = method;

    /// <summary>
    /// Name of method that caused exception
    /// </summary>
    public string Method
    {
        get
        {
            return _method;
        }
    }

    /// <summary>
    /// Return value of method that caused exception
    /// </summary>
    private readonly CKR _rv = rv;

    /// <summary>
    /// Return value of method that caused exception
    /// </summary>
    public CKR RV
    {
        get
        {
            return _rv;
        }
    }
}