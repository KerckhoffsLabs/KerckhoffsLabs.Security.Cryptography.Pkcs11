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
/// Marshalled as <see cref="CK_PKCS5_PBKD2_PARAMS2"/>, the corrected structure whose
/// <c>ulPasswordLen</c> is a value — except for a session on a module bound only through its v2.40
/// function list, which gets <see cref="CK_PKCS5_PBKD2_PARAMS"/>, whose <c>ulPasswordLen</c> is a
/// <c>CK_ULONG_PTR</c>. The two have the same size, so a module cannot tell them apart: one that reads
/// the v2.40 layout dereferences a length passed by value as an address and crashes the process
/// (NSS softoken before 3.52 does). Every v2.40 module reads the original structure, while the
/// corrected one, added by v2.40 Errata 01, is only guaranteed from v3.0.
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
    /// <param name="prfData">Additional data fed to the PRF alongside the salt; pass <c>default</c> if none.</param>
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
    /// <param name="prfData">Additional data fed to the PRF alongside the salt; pass <c>default</c> if none.</param>
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

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">The borrowed <see cref="SecurePassword"/> has been disposed.</exception>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        // Read straight from the caller's password into the scope, whose memory is zeroed when the call returns.
        ReadOnlySpan<byte> password = _borrowedPassword is { } borrowed ? borrowed.Password : _password;

        // A v2.40-only module reads ulPasswordLen through a pointer (see the type remarks).
        if (scope is SessionParameterScope { Session.IsBoundThroughV3Interface: false })
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
