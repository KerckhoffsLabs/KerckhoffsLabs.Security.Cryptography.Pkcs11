using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Token-specific identifier for an object
/// </summary>
public class ObjectHandle
{
    /// <summary>
    /// PKCS#11 handle of object
    /// </summary>
    protected NativeCULong _objectId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of object
    /// </summary>
    public ulong ObjectId
    {
        get
        {
            return Convert.ToUInt64(_objectId);
        }
    }

    /// <summary>
    /// Initializes new instance of ObjectHandle class with ObjectId set to CK_INVALID_HANDLE
    /// </summary>
    public ObjectHandle()
    {
        _objectId = CK.CK_INVALID_HANDLE;
    }

    /// <summary>
    /// Initializes new instance of ObjectHandle class
    /// </summary>
    /// <param name="objectId">PKCS#11 handle of object</param>
    public ObjectHandle(ulong objectId)
    {
        _objectId = ConvertUtils.UInt32FromUInt64(objectId);
    }
}