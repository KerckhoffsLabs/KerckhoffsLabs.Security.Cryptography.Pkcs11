using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Provides information about a particular mechanism
/// </summary>
public class MechanismInfo
{
    /// <summary>
    /// Mechanism
    /// </summary>
    protected CKM _mechanism = 0;

    /// <summary>
    /// Mechanism
    /// </summary>
    public CKM Mechanism
    {
        get
        {
            return _mechanism;
        }
    }

    /// <summary>
    /// The minimum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    protected NativeCULong _minKeySize = new (0);

    /// <summary>
    /// The minimum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    public ulong MinKeySize
    {
        get
        {
            return (ulong)_minKeySize;
        }
    }

    /// <summary>
    /// The maximum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    protected NativeCULong _maxKeySize = new (0);

    /// <summary>
    /// The maximum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    public ulong MaxKeySize
    {
        get
        {
            return (ulong)_maxKeySize;
        }
    }

    /// <summary>
    /// Flags specifying mechanism capabilities
    /// </summary>
    protected MechanismFlags _mechanismFlags = null;

    /// <summary>
    /// Flags specifying mechanism capabilities
    /// </summary>
    public MechanismFlags MechanismFlags
    {
        get
        {
            return _mechanismFlags;
        }
    }

    /// <summary>
    /// Converts low level CK_MECHANISM_INFO structure to high level MechanismInfo class
    /// </summary>
    /// <param name="mechanism">Mechanism</param>
    /// <param name="ck_mechanism_info">Low level CK_MECHANISM_INFO structure</param>
    protected internal MechanismInfo(CKM mechanism, CK_MECHANISM_INFO ck_mechanism_info)
    {
        _mechanism = mechanism;
        _minKeySize = ck_mechanism_info.MinKeySize;
        _maxKeySize = ck_mechanism_info.MaxKeySize;
        _mechanismFlags = new MechanismFlags(ck_mechanism_info.Flags);
    }
}