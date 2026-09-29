using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_PKCS5_PBKD2_PARAMS2"/>, the corrected (non-in/out) parameter
/// structure for CKM_PKCS5_PBKD2. Always uses <see cref="CKZ.CKZ_SALT_SPECIFIED"/> as the salt source
/// -- the only source the spec defines besides applying no salt at all, which PBKDF2 never does.
/// </summary>
/// <remarks>
/// The password is a secret, so unlike most parameter types this one owns something worth releasing:
/// its copy of the password is held in a pinned buffer (the garbage collector cannot move it and leave
/// stale copies behind) and zeroed on <see cref="Dispose"/>, or by the finalizer if the instance is
/// never disposed. Dispose it once the operation that uses it returns; a disposed instance refuses to
/// be marshalled.
/// </remarks>
public sealed class CkmPkcs5Pbkd2Params : MechanismParameters, IDisposable
{
    private readonly byte[] _salt;
    private readonly ulong _iterations;
    private readonly CKP _prf;
    private readonly byte[] _prfData;
    private byte[] _password;
    private GCHandle _passwordPin;
    private bool _disposed;

    /// <summary>
    /// Initializes the PBKDF2 parameters.
    /// </summary>
    /// <param name="salt">Salt bytes.</param>
    /// <param name="iterations">Number of iterations to perform when generating each block of keying material.</param>
    /// <param name="prf">Pseudo-random function used to generate the key.</param>
    /// <param name="password">Password to derive the key from.</param>
    /// <param name="prfData">Additional data fed to the PRF alongside the salt; pass <c>default</c> if none.</param>
    public CkmPkcs5Pbkd2Params(ReadOnlySpan<byte> salt, ulong iterations, CKP prf, ReadOnlySpan<byte> password, ReadOnlySpan<byte> prfData = default)
    {
        _salt = salt.ToArray();
        _iterations = iterations;
        _prf = prf;
        // Pin before copying, so the password is never written into a buffer the GC could relocate.
        _password = new byte[password.Length];
        _passwordPin = GCHandle.Alloc(_password, GCHandleType.Pinned);
        password.CopyTo(_password);
        _prfData = prfData.IsEmpty ? [] : prfData.ToArray();
    }

    /// <summary>The PRF, for policy evaluation.</summary>
    internal CKP Prf => _prf;

    /// <summary>Zeroes this instance's copy of the password and releases its GC pin.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_password);
        if (_passwordPin.IsAllocated) _passwordPin.Free();
        _password = [];
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net: zeroes the password even if <see cref="Dispose"/> was not called.</summary>
    ~CkmPkcs5Pbkd2Params() => Dispose();

    /// <inheritdoc/>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_PKCS5_PBKD2_PARAMS2
        {
            SaltSource = (NativeCULong)CKZ.CKZ_SALT_SPECIFIED,
            SaltSourceData = scope.Write(_salt),
            SaltSourceDataLen = (NativeCULong)_salt.Length,
            Iterations = (NativeCULong)_iterations,
            Prf = _prf.ToCULong(),
            PrfData = scope.Write(_prfData),
            PrfDataLen = (NativeCULong)_prfData.Length,
            Password = scope.Write(_password),
            PasswordLen = (NativeCULong)_password.Length,
        };
    }
}
