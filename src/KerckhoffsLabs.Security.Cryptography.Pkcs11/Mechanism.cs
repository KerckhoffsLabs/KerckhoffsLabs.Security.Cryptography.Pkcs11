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
    /// Creates mechanism of given type with object parameter. The mechanism takes ownership of
    /// <paramref name="parameter"/>.
    /// </summary>
    /// <remarks>
    /// Disposing the mechanism disposes the parameter object, releasing its unmanaged IV/AAD
    /// buffers deterministically instead of leaving them to its finalizer. Callers may still
    /// dispose the parameter themselves — disposal is idempotent, so the common
    /// <c>using var p = …; using var m = new Mechanism(…, p);</c> shape stays correct (a using
    /// declaration disposes in reverse order, so the mechanism goes first either way). What is no
    /// longer supported is sharing one parameter instance across two mechanisms: the first
    /// mechanism disposed frees the buffers the second still points at.
    /// </remarks>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter. Ownership transfers to the mechanism.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(ulong type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        // Owned from here: kept alive for the mechanism's lifetime and disposed with it.
        _mechanismParams = parameter;

        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CK_MECHANISM.CreateMechanism((NativeCULong)(type), lowLevelParams);
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter. The mechanism takes ownership of
    /// <paramref name="parameter"/>.
    /// </summary>
    /// <remarks>
    /// Disposing the mechanism disposes the parameter object, releasing its unmanaged IV/AAD
    /// buffers deterministically instead of leaving them to its finalizer. Callers may still
    /// dispose the parameter themselves — disposal is idempotent, so the common
    /// <c>using var p = …; using var m = new Mechanism(…, p);</c> shape stays correct (a using
    /// declaration disposes in reverse order, so the mechanism goes first either way). What is no
    /// longer supported is sharing one parameter instance across two mechanisms: the first
    /// mechanism disposed frees the buffers the second still points at.
    /// </remarks>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter. Ownership transfers to the mechanism.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(CKM type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        // Owned from here: kept alive for the mechanism's lifetime and disposed with it.
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
            // Order matters: the marshalled CK_MECHANISM block holds raw pointers into the
            // parameter object's buffers, so it is released before those buffers are.
            UnmanagedMemory.Free(ref _ckMechanism.Parameter);
            _ckMechanism.ParameterLen = new(0);

            if (disposing)
            {
                // The parameters are owned (see the constructor remarks), so their unmanaged IV/AAD
                // buffers are released here rather than left to the finalizer. Skipped on the
                // finalizer path: the parameter object is managed and has a finalizer of its own,
                // which may already have run.
                _mechanismParams?.Dispose();
            }

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
