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
    /// The mechanism type, kept so <see cref="Marshal"/> can rebuild the <c>CK_MECHANISM</c> without
    /// reaching into the legacy structure.
    /// </summary>
    private readonly NativeCULong _type;

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
    /// Builds the <c>CK_MECHANISM</c> for one native call, allocating the parameter block and any
    /// buffers it points at inside <paramref name="scope"/>.
    /// </summary>
    /// <param name="scope">Owns every byte allocated here; released by the caller once the call returns.</param>
    /// <param name="marshalledParams">
    /// Receives the interop struct written into <paramref name="scope"/>, to be handed back to
    /// <see cref="AbsorbOutput"/> once the native call returns, or <see langword="null"/> for a
    /// mechanism with no high-level parameters.
    /// </param>
    /// <returns>The structure to hand to the native entry point.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the mechanism has been disposed.</exception>
    /// <remarks>
    /// Deliberately stateless: the marshalled struct is returned to the caller rather than cached on
    /// this instance. One <c>Mechanism</c> may be used by two operations at once — different sessions,
    /// or the same instance passed as both arguments of <c>DecryptVerify</c> — and a cache would let
    /// the second marshal overwrite the first, so both absorbs would read the second block and the
    /// first operation's output would be silently lost.
    /// </remarks>
    internal CK_MECHANISM Marshal(MechanismParameterScope scope, out object? marshalledParams)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Mechanisms built with no parameter, or with a raw byte[] one, have nothing to rebuild: the
        // constructor already produced the CK_MECHANISM (null Parameter, or a block it owns), so hand
        // that value back unchanged.
        if (_mechanismParams is null)
        {
            marshalledParams = null;
            return _ckMechanism;
        }

        object lowLevel = _mechanismParams.BuildMarshalable(scope);
        marshalledParams = lowLevel;

        int size = UnmanagedMemory.SizeOf(lowLevel.GetType());
        IntPtr block = scope.Allocate(size);
        UnmanagedMemory.Write(block, lowLevel);

        return new CK_MECHANISM
        {
            Mechanism = _type,
            Parameter = block,
            ParameterLen = (NativeCULong)size,
        };
    }

    /// <summary>
    /// Copies any token output out of the block built by <see cref="Marshal"/> and back into the
    /// parameter object's managed state. Must run after the native call returns and before the scope
    /// passed to <see cref="Marshal"/> is disposed — that scope owns the memory being read.
    /// </summary>
    /// <param name="marshalledParams">
    /// The value <see cref="Marshal"/> produced for this operation. <see langword="null"/> is a no-op,
    /// which is what parameterless and <c>byte[]</c> mechanisms pass.
    /// </param>
    internal void AbsorbOutput(object? marshalledParams)
    {
        if (_mechanismParams is null || marshalledParams is null)
            return;

        _mechanismParams.AbsorbOutput(marshalledParams);
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
        _type = (NativeCULong)type;
        _ckMechanism = CK_MECHANISM.CreateMechanism(_type);
    }

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(CKM type)
    {
        _type = type.ToCULong();
        _ckMechanism = CK_MECHANISM.CreateMechanism(type);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(ulong type, byte[] parameter)
    {
        _type = (NativeCULong)type;
        _ckMechanism = CK_MECHANISM.CreateMechanism(_type, parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    public Mechanism(CKM type, byte[] parameter)
    {
        _type = type.ToCULong();
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
        ThrowIfAlreadyOwned(parameter);

        // Owned from here: kept alive for the mechanism's lifetime and disposed with it.
        _mechanismParams = parameter;

        _type = (NativeCULong)type;
        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CK_MECHANISM.CreateMechanism(_type, lowLevelParams);
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
        ThrowIfAlreadyOwned(parameter);

        // Owned from here: kept alive for the mechanism's lifetime and disposed with it.
        _mechanismParams = parameter;

        _type = type.ToCULong();
        object lowLevelParams = _mechanismParams.ToMarshalableStructure();
        _ckMechanism = CK_MECHANISM.CreateMechanism(type, lowLevelParams);
    }

    /// <summary>
    /// Rejects a parameter instance that another mechanism already owns. Each mechanism marshals its
    /// own copy of the parameter struct — pointer fields and all — so sharing one instance would
    /// leave the second mechanism holding addresses that the first frees on disposal, and the token
    /// would be handed released memory. Failing here points at the actual mistake.
    /// </summary>
    private static void ThrowIfAlreadyOwned(MechanismParameters parameter)
    {
        if (!parameter.TryClaimOwnership())
        {
            throw new InvalidOperationException(
                $"This {nameof(MechanismParameters)} instance already belongs to another {nameof(Mechanism)}. " +
                "A mechanism disposes the parameters it owns, so sharing one instance would leave the other " +
                "mechanism pointing at freed buffers. Construct a separate parameter object for each mechanism.");
        }
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
