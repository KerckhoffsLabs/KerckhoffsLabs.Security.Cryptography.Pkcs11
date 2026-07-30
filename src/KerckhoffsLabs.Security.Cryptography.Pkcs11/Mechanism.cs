using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// The strongly-typed managed counterpart of <c>CK_MECHANISM</c>, pairing a mechanism type with its
/// parameters.
/// </summary>
public sealed class Mechanism
{
    /// <summary>
    /// The mechanism type, from which <see cref="Marshal"/> builds the <c>CK_MECHANISM</c>.
    /// </summary>
    private readonly NativeCULong _type;

    /// <summary>
    /// The raw parameter block for the <c>byte[]</c> constructors, copied into the call scope by
    /// <see cref="Marshal"/>. <see langword="null"/> for every other constructor.
    /// </summary>
    private readonly byte[]? _rawParameter;

    /// <summary>
    /// The type of mechanism
    /// </summary>
    public ulong Type => (ulong)_type;

    /// <summary>
    /// Exposes the high-level mechanism parameters for test inspection (visible to the test assembly via InternalsVisibleTo).
    /// Returns <c>null</c> when the mechanism was constructed without parameters.
    /// </summary>
    internal MechanismParameters? Parameters => _mechanismParams;

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
    /// <remarks>
    /// Deliberately stateless: the marshalled struct is returned to the caller rather than cached on
    /// this instance. One <c>Mechanism</c> may be used by two operations at once — different sessions,
    /// or the same instance passed as both arguments of <c>DecryptVerify</c> — and a cache would let
    /// the second marshal overwrite the first, so both absorbs would read the second block and the
    /// first operation's output would be silently lost.
    /// </remarks>
    internal CK_MECHANISM Marshal(MechanismParameterScope scope, out object? marshalledParams)
    {
        // No high-level parameters: either no parameter at all, or a raw byte[] one. Both are a
        // straight copy into the scope, and neither has output to absorb. `scope.Write` yields
        // IntPtr.Zero for an empty span, which is what PKCS#11 expects for an absent parameter.
        if (_mechanismParams is null)
        {
            marshalledParams = null;
            ReadOnlySpan<byte> raw = _rawParameter;
            return new CK_MECHANISM
            {
                Mechanism = _type,
                Parameter = scope.Write(raw),
                ParameterLen = (NativeCULong)raw.Length,
            };
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
    public Mechanism(ulong type) => _type = (NativeCULong)type;

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(CKM type) => _type = type.ToCULong();

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied so later changes to the array are ignored</param>
    public Mechanism(ulong type, byte[] parameter)
    {
        _type = (NativeCULong)type;
        _rawParameter = [.. parameter];
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied so later changes to the array are ignored</param>
    public Mechanism(CKM type, byte[] parameter)
    {
        _type = type.ToCULong();
        _rawParameter = [.. parameter];
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter.
    /// </summary>
    /// <remarks>
    /// The parameter object is a managed descriptor holding nothing unmanaged, so the mechanism only
    /// keeps a reference to it: each native call marshals it into that call's own scope. Sharing one
    /// parameter instance across several mechanisms is therefore safe.
    /// </remarks>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(ulong type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        _mechanismParams = parameter;
        _type = (NativeCULong)type;
    }

    /// <summary>
    /// Creates mechanism of given type with object parameter.
    /// </summary>
    /// <remarks>
    /// The parameter object is a managed descriptor holding nothing unmanaged, so the mechanism only
    /// keeps a reference to it: each native call marshals it into that call's own scope. Sharing one
    /// parameter instance across several mechanisms is therefore safe.
    /// </remarks>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(CKM type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        _mechanismParams = parameter;
        _type = type.ToCULong();
    }
}
