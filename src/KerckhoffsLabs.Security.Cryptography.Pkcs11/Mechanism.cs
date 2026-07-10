using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// The strongly-typed managed counterpart of <c>CK_MECHANISM</c>, pairing a mechanism type with its
/// parameters.
/// </summary>
public sealed class Mechanism : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Low level mechanism structure
    /// </summary>
    private CK_MECHANISM _ckMechanism;

    /// <summary>
    /// The type of mechanism
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the mechanism has been disposed.</exception>
    public ulong Type
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return (ulong)_ckMechanism.Mechanism;
        }
    }

    /// <summary>
    /// Exposes the high-level mechanism parameters for test inspection (visible to the test assembly via InternalsVisibleTo).
    /// Returns <c>null</c> when the mechanism was constructed without parameters.
    /// </summary>
    internal MechanismParameters? Parameters
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _mechanismParams;
        }
    }

    /// <summary>
    /// Returns managed object corresponding to CK_MECHANISM structure that can be marshaled to an unmanaged block of memory
    /// </summary>
    /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
    internal object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _ckMechanism;
    }

    /// <summary>
    /// High level object with mechanism parameters
    /// </summary>
    private readonly MechanismParameters? _mechanismParams = null;

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(ulong type)
    {
        _ckMechanism = CK_MECHANISM.CreateMechanism((NativeCULong)type);
    }

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(CKM type)
    {
        _ckMechanism = CK_MECHANISM.CreateMechanism(type);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(ulong type, byte[] parameter)
    {
        _ckMechanism = CK_MECHANISM.CreateMechanism((NativeCULong)(type), parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(CKM type, byte[] parameter)
    {
        _ckMechanism = CK_MECHANISM.CreateMechanism(type, parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(ulong type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        // Keep reference to parameter so GC will not free it while mechanism exists
        _mechanismParams = parameter;

        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CK_MECHANISM.CreateMechanism((NativeCULong)(type), lowLevelParams);
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(CKM type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        // Keep reference to parameter so GC will not free it while mechanism exists
        _mechanismParams = parameter;

        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CK_MECHANISM.CreateMechanism(type, lowLevelParams);
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
    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
            }

            // Dispose unmanaged objects
            UnmanagedMemory.Free(ref _ckMechanism.Parameter);
            _ckMechanism.ParameterLen = new(0);

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
