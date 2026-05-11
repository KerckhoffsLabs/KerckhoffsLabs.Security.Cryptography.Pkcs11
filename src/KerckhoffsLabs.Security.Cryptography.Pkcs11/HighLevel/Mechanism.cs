using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Mechanism and its parameters (CK_MECHANISM alternative)
/// </summary>
public class Mechanism
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    protected bool _disposed = false;

    /// <summary>
    /// Low level mechanism structure
    /// </summary>
    protected CK_MECHANISM _ckMechanism;

    /// <summary>
    /// The type of mechanism
    /// </summary>
    public ulong Type
    {
        get
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            return Convert.ToUInt64(_ckMechanism.Mechanism);
        }
    }

    /// <summary>
    /// Returns managed object corresponding to CK_MECHANISM structure that can be marshaled to an unmanaged block of memory
    /// </summary>
    /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
    public object ToMarshalableStructure()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        return _ckMechanism;
    }

    /// <summary>
    /// High level object with mechanism parameters
    /// </summary>
    protected MechanismParams _mechanismParams = null;

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(ulong type)
    {
        _ckMechanism = CkmUtils.CreateMechanism(Convert.ToUInt64(type));
    }

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(CKM type)
    {
        _ckMechanism = CkmUtils.CreateMechanism(type);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(ulong type, byte[] parameter)
    {
        _ckMechanism = CkmUtils.CreateMechanism((NativeCULong)(type), parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(CKM type, byte[] parameter)
    {
        _ckMechanism = CkmUtils.CreateMechanism(type, parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(ulong type, MechanismParams parameter)
    {
        if (parameter == null)
            throw new ArgumentNullException("parameter");

        // Keep reference to parameter so GC will not free it while mechanism exists
        _mechanismParams = parameter;

        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CkmUtils.CreateMechanism((NativeCULong)(type), lowLevelParams);
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(CKM type, MechanismParams parameter)
    {
        if (parameter == null)
            throw new ArgumentNullException("parameter");

        // Keep reference to parameter so GC will not free it while mechanism exists
        _mechanismParams = parameter;

        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CkmUtils.CreateMechanism(type, lowLevelParams);
    }

    #region IDisposable
    
    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    
    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
            }
            
            // Dispose unmanaged objects
            UnmanagedMemory.Free(ref _ckMechanism.Parameter);
            _ckMechanism.ParameterLen = new (0);
            
            _disposed = true;
        }
    }
    
    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Mechanism()
    {
        Dispose(false);
    }
    
    #endregion
}