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
    /// The raw parameter block for the <c>byte[]</c> and <c>ReadOnlySpan&lt;byte&gt;</c> constructors,
    /// copied into the call scope by <see cref="Marshal"/>. <see langword="null"/> for every other
    /// constructor.
    /// </summary>
    private readonly byte[]? _rawParameter;

    /// <summary>
    /// High level object with mechanism parameters
    /// </summary>
    private readonly MechanismParameters? _mechanismParams = null;

    // The constructors form two blocks. The CKM-typed block below is the ordinary API and carries the
    // documentation; the ulong-typed block after it is the vendor escape hatch and inherits it. Within
    // each block they run from least to most raw — no parameter, then a typed descriptor, then a block
    // of bytes the caller laid out — which is also the order of preference for reaching for them.

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type</param>
    public Mechanism(CKM type) => _type = type.ToCULong();

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

    /// <summary>
    /// Creates mechanism of given type whose parameter is a raw block of bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="parameter"/> becomes <c>pParameter</c> verbatim, so it must be the mechanism's
    /// <i>entire</i> parameter as the token expects to receive it. That is the right shape only where
    /// PKCS#11 defines the parameter as a bare block — an IV for the CBC and CFB modes — or where a
    /// vendor mechanism's block is one this library cannot describe. A mechanism whose parameter is a
    /// <c>CK_*_PARAMS</c> struct takes a <see cref="MechanismParameters"/> descriptor instead; passing
    /// the struct's leading field here produces a block the token rejects as malformed.
    /// </para>
    /// <para>
    /// The span overloads exist for callers that already hold the block as a span — the CBC and CFB
    /// modes do, on every operation. Taking an array there forced a <c>ToArray()</c> at the call site
    /// purely to satisfy the signature, and the constructor's own defensive copy then made that first
    /// array garbage; one copy is enough.
    /// </para>
    /// </remarks>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied into the mechanism</param>
    public Mechanism(CKM type, ReadOnlySpan<byte> parameter)
    {
        _type = type.ToCULong();
        _rawParameter = parameter.ToArray();
    }

    /// <inheritdoc cref="Mechanism(CKM, ReadOnlySpan{byte})"/>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied so later changes to the array are ignored</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(CKM type, byte[] parameter)
    {
        _type = type.ToCULong();
        _rawParameter = [.. parameter];
    }

    // The ulong-typed block: mechanisms outside CKM. Taking the type as a raw value rather than an
    // invented enum member is the point — casting to CKM would assert the value is one this library
    // knows, and for a vendor mechanism it is not.

    /// <inheritdoc cref="Mechanism(CKM)"/>
    /// <param name="type">Mechanism type</param>
    public Mechanism(ulong type) => _type = (NativeCULong)type;

    /// <inheritdoc cref="Mechanism(CKM, MechanismParameters)"/>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(ulong type, MechanismParameters parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        _mechanismParams = parameter;
        _type = (NativeCULong)type;
    }

    /// <inheritdoc cref="Mechanism(CKM, ReadOnlySpan{byte})"/>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied into the mechanism</param>
    public Mechanism(ulong type, ReadOnlySpan<byte> parameter)
    {
        _type = (NativeCULong)type;
        _rawParameter = parameter.ToArray();
    }

    /// <inheritdoc cref="Mechanism(CKM, ReadOnlySpan{byte})"/>
    /// <param name="type">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter, copied so later changes to the array are ignored</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <c>null</c>.</exception>
    public Mechanism(ulong type, byte[] parameter)
    {
        _type = (NativeCULong)type;
        _rawParameter = [.. parameter];
    }

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

        // A vendor block arrives already laid out: it has no [PackedForPkcs11] struct for
        // UnmanagedMemory to marshal, because the generator never saw the vendor's type.
        if (lowLevel is Pkcs11ParameterBlock prebuilt)
        {
            return new CK_MECHANISM
            {
                Mechanism = _type,
                Parameter = prebuilt.Pointer,
                ParameterLen = (NativeCULong)prebuilt.Length,
            };
        }

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
}
