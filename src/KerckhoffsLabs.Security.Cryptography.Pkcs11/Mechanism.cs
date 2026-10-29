using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
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
    /// The raw parameter block for the <c>ReadOnlySpan&lt;byte&gt;</c> constructor, copied into the
    /// call scope by <see cref="Marshal"/>. <see langword="null"/> for every other constructor.
    /// </summary>
    private readonly byte[]? _rawParameter;

    /// <summary>
    /// High level object with mechanism parameters
    /// </summary>
    private readonly MechanismParameters? _mechanismParams = null;

    // The constructors run from least to most raw — no parameter, then a typed descriptor, then a block
    // of bytes the caller laid out — which is also the order of preference for reaching for them. A
    // vendor mechanism is a CKM value too: CKM is ulong-backed like CK_MECHANISM_TYPE, so
    // (CKM)0x80001234 names it without any loss.

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="type">Mechanism type. A vendor mechanism is passed as its value cast to <see cref="CKM"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c> (32 bits on Windows).</exception>
    public Mechanism(CKM type) => _type = type.ToCULong();

    /// <summary>
    /// Creates mechanism of given type with object parameter.
    /// </summary>
    /// <remarks>
    /// The parameter object is a managed descriptor holding nothing unmanaged, so the mechanism only
    /// keeps a reference to it: each native call marshals it into that call's own scope. Sharing one
    /// parameter instance across several mechanisms is therefore safe.
    /// </remarks>
    /// <param name="type">Mechanism type. A vendor mechanism is passed as its value cast to <see cref="CKM"/>.</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="parameter"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c> (32 bits on Windows).</exception>
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
    /// For a standard mechanism whose parameter has a fixed layout, the length is checked here. A token is
    /// told the parameter's length, but one that reads the whole layout regardless would read past a
    /// shorter block into whatever memory follows it. The block must be:
    /// </para>
    /// <list type="bullet">
    /// <item>an IV of the cipher's block size for a block cipher's CBC, OFB, CFB or CTS mode (16 bytes
    /// for AES, Camellia, ARIA, SEED and Twofish; 8 for DES, Triple DES, Blowfish, CAST, CDMF and IDEA);</item>
    /// <item>empty or one IV for a mechanism whose IV is optional (<c>CKM_AES_KEY_WRAP</c> and
    /// <c>CKM_AES_KEY_WRAP_KWP</c>, the GOST 28147 modes);</item>
    /// <item>the mechanism's <c>CK_*_PARAMS</c> struct at its size on this platform, as this library
    /// marshals it (packed on Windows, natural elsewhere), or empty where the struct is optional. A struct
    /// with pointers in it still needs them to be valid, which a raw block leaves to the caller; prefer
    /// the <see cref="MechanismParameters"/> descriptor where there is one.</item>
    /// </list>
    /// <para>
    /// A mechanism with a variable-length parameter, a vendor mechanism, or one this library has no layout
    /// for takes a block of any length.
    /// </para>
    /// <para>
    /// A <c>byte[]</c> converts to the span implicitly, so this one overload serves both.
    /// </para>
    /// </remarks>
    /// <param name="type">Mechanism type. A vendor mechanism is passed as its value cast to <see cref="CKM"/>.</param>
    /// <param name="parameter">
    /// Mechanism parameter, copied into the mechanism, so later changes to the caller's buffer are
    /// ignored. An empty parameter marshals as a null <c>pParameter</c> with zero length.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c> (32 bits on Windows).</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="type"/>'s parameter has a fixed layout and <paramref name="parameter"/> is not its length.</exception>
    public Mechanism(CKM type, ReadOnlySpan<byte> parameter)
    {
        _type = type.ToCULong();
        if (MechanismParameterLength.For(type) is { } rule && !rule.Lengths.Contains(parameter.Length))
            throw new ArgumentException(MechanismParameterLength.Describe(type, rule, parameter.Length), nameof(parameter));
        _rawParameter = parameter.ToArray();
    }

    /// <summary>
    /// The mechanism type. It may be vendor-defined (see <see cref="IsVendorDefined"/>) or newer than
    /// this library, in which case it names no <see cref="CKM"/> member; <c>Enum.IsDefined</c> tells
    /// the two apart.
    /// </summary>
    public CKM Type => (CKM)(ulong)_type;

    /// <summary>
    /// Whether the mechanism type is vendor-defined (<c>≥ CKM_VENDOR_DEFINED</c>, <c>0x80000000</c>).
    /// </summary>
    /// <remarks>
    /// It answers what the mechanism <i>is</i>, not merely whether this library has heard of it: a
    /// standard mechanism newer than <see cref="CKM"/> is not vendor-defined, yet names no member.
    /// </remarks>
    public bool IsVendorDefined => Type >= CKM.CKM_VENDOR_DEFINED;

    /// <summary>
    /// Exposes the high-level mechanism parameters for test inspection (visible to the test assembly via InternalsVisibleTo).
    /// Returns <see langword="null"/> when the mechanism was constructed without parameters.
    /// </summary>
    internal MechanismParameters? Parameters => _mechanismParams;

    /// <summary>
    /// Whether the mechanism carries a non-empty raw parameter block (the <c>ReadOnlySpan&lt;byte&gt;</c>
    /// constructor). A crypto policy cannot read such a block, so it tells "no parameter" apart from
    /// "a parameter it cannot inspect" with this.
    /// </summary>
    internal bool HasRawParameter => _rawParameter is { Length: > 0 };

    /// <summary>
    /// Builds the <c>CK_MECHANISM</c> for one native call, allocating the parameter block and any
    /// buffers it points at inside <paramref name="scope"/>.
    /// </summary>
    /// <param name="scope">Owns every byte allocated here; released by the caller once the call returns.</param>
    /// <param name="marshalledParams">
    /// Receives the parameter block written into <paramref name="scope"/>, to be handed back to
    /// <see cref="AbsorbOutput"/> once the native call returns, or <see langword="null"/> for a
    /// mechanism with no high-level parameters.
    /// </param>
    /// <returns>The structure to hand to the native entry point.</returns>
    /// <remarks>
    /// Deliberately stateless: the block is returned to the caller rather than cached on
    /// this instance. One <c>Mechanism</c> may be used by two operations at once — different sessions,
    /// or the same instance passed as both arguments of <c>DecryptVerify</c> — and a cache would let
    /// the second marshal overwrite the first, so both absorbs would read the second block and the
    /// first operation's output would be silently lost.
    /// </remarks>
    internal CK_MECHANISM Marshal(MechanismParameterScope scope, out Pkcs11ParameterBlock? marshalledParams)
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

        Pkcs11ParameterBlock block = _mechanismParams.BuildMarshalable(scope);
        marshalledParams = block;

        return new CK_MECHANISM
        {
            Mechanism = _type,
            Parameter = block.Pointer,
            ParameterLen = (NativeCULong)block.Length,
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
    internal void AbsorbOutput(Pkcs11ParameterBlock? marshalledParams)
    {
        if (_mechanismParams is null || marshalledParams is not { } block)
            return;

        _mechanismParams.AbsorbOutput(block);
    }
}
