using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_PKCS5_PBKD2_PARAMS2"/>, the corrected (non-in/out) parameter
/// structure for CKM_PKCS5_PBKD2. Always uses <see cref="CKZ.CKZ_SALT_SPECIFIED"/> as the salt source
/// -- the only source the spec defines besides applying no salt at all, which PBKDF2 never does.
/// </summary>
public sealed class CkmPkcs5Pbkd2Params : MechanismParameters
{
    private readonly byte[] _salt;
    private readonly ulong _iterations;
    private readonly CKP _prf;
    private readonly byte[] _prfData;
    private readonly byte[] _password;

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
        _password = password.ToArray();
        _prfData = prfData.IsEmpty ? [] : prfData.ToArray();
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
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
