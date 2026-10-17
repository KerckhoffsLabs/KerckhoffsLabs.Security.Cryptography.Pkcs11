using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for the CKM_PKCS5_PBKD2 parameters. Always uses
/// <see cref="CKZ.CKZ_SALT_SPECIFIED"/> as the salt source -- the only source the spec defines besides
/// applying no salt at all, which PBKDF2 never does.
/// </summary>
/// <remarks>
/// <para>
/// Marshalled as <see cref="CK_PKCS5_PBKD2_PARAMS2"/>, the structure v2.40 Errata 01 and v3.0
/// specify, whose <c>ulPasswordLen</c> is a value. A module that reads the original v2.40
/// <see cref="CK_PKCS5_PBKD2_PARAMS"/>, whose <c>ulPasswordLen</c> is a <c>CK_ULONG_PTR</c>, gets that
/// instead: one detected as such, directly or behind a proxy, or any module when
/// <see cref="Pkcs11LibraryOptions.Pbkdf2ParametersLayout"/> says so. Sent the wrong one, such a module
/// dereferences the length as an address and crashes the process (see
/// <see cref="Pkcs11.Pbkdf2ParametersLayout"/>).
/// </para>
/// <para>
/// The password is a secret, and how it is held depends on the constructor. The
/// <see cref="SecurePassword"/> constructor borrows the caller's password and keeps no copy: it is
/// read only while a call is being marshalled, into per-call memory that is zeroed when the call
/// returns, and zeroing it for good is the <see cref="SecurePassword"/>'s job — dispose it once the
/// operation is done. Prefer that constructor.
/// </para>
/// <para>
/// The span constructor keeps its own copy for the life of this instance, in an array allocated on
/// the pinned object heap so the garbage collector never moves it and leaves stale images behind.
/// That copy is not zeroed: like every parameter type, this one needs no releasing and can be shared
/// across mechanisms.
/// </para>
/// </remarks>
public sealed class CkmPkcs5Pbkd2Params : MechanismParameters
{
    private readonly byte[] _salt;
    private readonly int _iterations;
    private readonly CKP _prf;
    private readonly byte[] _prfData;
    private readonly byte[]? _password;
    private readonly SecurePassword? _borrowedPassword;

    /// <summary>
    /// Initializes the PBKDF2 parameters with a copy of <paramref name="password"/>, kept pinned and
    /// never zeroed. Prefer the <see cref="SecurePassword"/> overload, which keeps no copy.
    /// </summary>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="iterations">Number of iterations to perform when generating each block of keying material.</param>
    /// <param name="prf">Pseudo-random function used to generate the key.</param>
    /// <param name="password">Password to derive the key from. May be empty.</param>
    /// <param name="prfData">Additional data fed to the PRF alongside the salt; pass <see langword="default"/> if none.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is negative.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The two constructors differ in the required password parameter's type (owned span vs. borrowed SecurePassword), so no call site is ambiguous.")]
    public CkmPkcs5Pbkd2Params(ReadOnlySpan<byte> salt, int iterations, CKP prf, ReadOnlySpan<byte> password, ReadOnlySpan<byte> prfData = default)
        : this(prf, iterations, salt, prfData)
    {
        _password = GC.AllocateArray<byte>(password.Length, pinned: true);
        password.CopyTo(_password);
    }

    /// <summary>
    /// Initializes the PBKDF2 parameters with a borrowed <paramref name="password"/>: no copy is kept,
    /// and it is read only while a call is being marshalled.
    /// </summary>
    /// <remarks>
    /// The caller keeps ownership of <paramref name="password"/> and must keep it undisposed until
    /// every operation using these parameters has returned; once it is disposed, those operations
    /// throw <see cref="ObjectDisposedException"/>.
    /// </remarks>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="iterations">Number of iterations to perform when generating each block of keying material.</param>
    /// <param name="prf">Pseudo-random function used to generate the key.</param>
    /// <param name="password">Password to derive the key from. Borrowed, not owned.</param>
    /// <param name="prfData">Additional data fed to the PRF alongside the salt; pass <see langword="default"/> if none.</param>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is negative.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "The two constructors differ in the required password parameter's type (owned span vs. borrowed SecurePassword), so no call site is ambiguous.")]
    public CkmPkcs5Pbkd2Params(ReadOnlySpan<byte> salt, int iterations, CKP prf, SecurePassword password, ReadOnlySpan<byte> prfData = default)
        : this(prf, iterations, salt, prfData)
    {
        ArgumentNullException.ThrowIfNull(password);
        _borrowedPassword = password;
    }

    // The fields every constructor sets. The PRF leads so this signature cannot be mistaken for the
    // public span constructor's.
    private CkmPkcs5Pbkd2Params(CKP prf, int iterations, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> prfData)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(iterations);
        _salt = salt.ToArray();
        _iterations = iterations;
        _prf = prf;
        _prfData = prfData.IsEmpty ? [] : prfData.ToArray();
    }

    /// <summary>The PRF, for policy evaluation.</summary>
    internal CKP Prf => _prf;

    // What NSS softoken reports as the manufacturer of the module and of each of its slots.
    private const string NssManufacturer = "Mozilla Foundation";

    /// <summary>Whether a slot belongs to NSS softoken, loaded directly or behind a proxy.</summary>
    internal static bool IsNss(SlotInfo info) => info.ManufacturerId == NssManufacturer;

    /// <summary>
    /// Whether an NSS softoken slot reads the original <see cref="CK_PKCS5_PBKD2_PARAMS"/>: true before
    /// 3.114. NSS reports its release as each slot's <c>hardwareVersion</c>, and its manufacturer there
    /// too, so a slot is recognized behind a proxy such as p11-kit's, which reports itself in
    /// <c>C_GetInfo</c> but passes its modules' slot information on.
    /// </summary>
    /// <remarks>
    /// NSS softoken dereferences <c>ulPasswordLen</c> unconditionally up to 3.113, including from 3.52
    /// on, where it implements v3.0 and is bound through <c>C_GetInterface</c>. 3.114 accepts either
    /// structure, and can be built to accept only the corrected one, so from 3.114 on it gets that.
    /// </remarks>
    internal static bool ReadsPasswordLengthByReference(SlotInfo info)
        => IsNss(info) && IsNssBefore3_114(info.HardwareVersion);

    /// <summary>
    /// Whether a module that is not NSS reads the original <see cref="CK_PKCS5_PBKD2_PARAMS"/>, judged
    /// from the Cryptoki version it reports in <c>C_GetInfo</c>: true before 2.40. The corrected
    /// structure first appeared in v2.40 Errata 01, so an earlier module can only read the original; a
    /// v2.40 module may read either, and gets the standard structure.
    /// </summary>
    internal static bool ReadsPasswordLengthByReference(LibraryInfo info)
        => info.CryptokiVersion < new Version(2, 40);

    private static bool IsNssBefore3_114(Version version) => version is { Major: 3, Minor: < 114 };

    /// <summary>
    /// The longest <c>ulPasswordLen</c> NSS softoken reads as a value when the two layouts share their size
    /// (<c>CK_PKCS5_PBKD2_PARAMS_PTR_BOUNDARY</c> in its <c>pkcs11n.h</c>); anything longer it takes for a pointer.
    /// </summary>
    internal const int AmbiguousPasswordLengthBoundary = 8192;

    /// <summary>Whether <see cref="CK_PKCS5_PBKD2_PARAMS"/> and <see cref="CK_PKCS5_PBKD2_PARAMS2"/> have the same size here.</summary>
    internal static bool LayoutsShareTheirSize
        => Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS>() == Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS2>();

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">The borrowed <see cref="SecurePassword"/> has been disposed.</exception>
    /// <exception cref="NotSupportedException">The password is longer than 8192 bytes and would go out as
    /// <see cref="CK_PKCS5_PBKD2_PARAMS2"/> where both layouts have the same size.</exception>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        // Read straight from the caller's password into the scope, whose memory is zeroed when the call returns.
        ReadOnlySpan<byte> password = _borrowedPassword is { } borrowed ? borrowed.Password : _password;

        // A module that reads the original structure gets ulPasswordLen through a pointer (see the type remarks).
        if (scope is SessionParameterScope session && session.Session.ResolvePbkdf2PasswordLengthByReference())
        {
            return scope.WriteParameter(new CK_PKCS5_PBKD2_PARAMS
            {
                SaltSource = (NativeCULong)CKZ.CKZ_SALT_SPECIFIED,
                SaltSourceData = scope.Write(_salt),
                SaltSourceDataLen = (NativeCULong)_salt.Length,
                Iterations = (NativeCULong)(ulong)_iterations,
                Prf = CkULong.From((ulong)_prf, "prf"),
                PrfData = scope.Write(_prfData),
                PrfDataLen = (NativeCULong)_prfData.Length,
                Password = scope.Write(password),
                PasswordLen = scope.WriteStruct((NativeCULong)password.Length),
            });
        }

        // Where both structures have the same size (64-bit Unix), a module accepting either cannot tell them
        // apart by ulParameterLen. NSS 3.114+ then reads a ulPasswordLen above 8192 as the v2.40 pointer and
        // dereferences it, which takes the process down; refuse such a password rather than send it.
        if (password.Length > AmbiguousPasswordLengthBoundary && LayoutsShareTheirSize)
            throw new NotSupportedException(
                $"A PBKDF2 password longer than {AmbiguousPasswordLengthBoundary} bytes cannot be sent as " +
                "CK_PKCS5_PBKD2_PARAMS2 on this platform: modules that accept both PBKDF2 parameter layouts, " +
                "NSS softoken from 3.114 among them, read such a length as a pointer and crash the process. " +
                "Hash a longer password down first.");

        return scope.WriteParameter(new CK_PKCS5_PBKD2_PARAMS2
        {
            SaltSource = (NativeCULong)CKZ.CKZ_SALT_SPECIFIED,
            SaltSourceData = scope.Write(_salt),
            SaltSourceDataLen = (NativeCULong)_salt.Length,
            Iterations = (NativeCULong)(ulong)_iterations,
            Prf = CkULong.From((ulong)_prf, "prf"),
            PrfData = scope.Write(_prfData),
            PrfDataLen = (NativeCULong)_prfData.Length,
            Password = scope.Write(password),
            PasswordLen = (NativeCULong)password.Length,
        });
    }
}
