using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="Rfc2898DeriveBytes"/>-shaped wrapper that runs PBKDF2 (RFC 8018) on a
/// PKCS#11 token (<c>CKM_PKCS5_PBKD2</c>). <c>Rfc2898DeriveBytes</c> is sealed in the BCL, so this is
/// a wrapper, not a subclass; constructor and method shapes mirror it, including its verified
/// behavior of <see cref="GetBytes"/> returning successive slices of one continuous PBKDF2 byte
/// stream rather than independent derivations.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="SP800108HmacCounterKdfPkcs11"/> or an HKDF wrapper, PBKDF2 has no pre-existing
/// token key to wrap: the password is the input, so this type holds a <see cref="Pkcs11Workspace"/>
/// directly and creates an ephemeral token key on every <see cref="GetBytes"/> call.
/// </para>
/// <para>
/// <b>Requires <see cref="Pkcs11Workspace.AllowInsecure"/>.</b> Every derivation here returns
/// <c>byte[]</c>, so the value must be read back off the token — the library's single secure-defaults
/// gate declines to create the extractable, non-sensitive key that read-back needs. Use
/// <c>AllowInsecureScope()</c> to opt in for one operation.
/// </para>
/// </remarks>
public sealed class Rfc2898DeriveBytesPkcs11 : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly byte[] _password;
    private byte[] _salt;
    private int _iterationCount;
    private readonly CKP _prf;
    private int _position;
    private bool _disposed;

    /// <summary>Initializes the PBKDF2 wrapper from a password and salt.</summary>
    /// <param name="workspace">The workspace to run <c>CKM_PKCS5_PBKD2</c> in. Borrowed, not owned.</param>
    /// <param name="password">The password to derive from.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="iterations">Number of PBKDF2 iterations. Must be positive.</param>
    /// <param name="hashAlgorithm">PRF hash — SHA1, SHA256, SHA384, or SHA512.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="workspace"/>, <paramref name="password"/>, or <paramref name="salt"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="iterations"/> is not positive.</exception>
    /// <exception cref="NotSupportedException">Thrown for an unsupported PRF hash.</exception>
    public Rfc2898DeriveBytesPkcs11(Pkcs11Workspace workspace, byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
        : this(workspace, (ReadOnlySpan<byte>)(password ?? throw new ArgumentNullException(nameof(password))),
              salt ?? throw new ArgumentNullException(nameof(salt)), iterations, hashAlgorithm)
    {
    }

    /// <summary>Initializes the PBKDF2 wrapper from a password and salt.</summary>
    /// <inheritdoc cref="Rfc2898DeriveBytesPkcs11(Pkcs11Workspace, byte[], byte[], int, HashAlgorithmName)"/>
    public Rfc2898DeriveBytesPkcs11(Pkcs11Workspace workspace, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);
        _prf = PrfForHash(hashAlgorithm);
        _workspace = workspace;
        _password = password.ToArray();
        _salt = salt.ToArray();
        _iterationCount = iterations;
    }

    /// <summary>Initializes the PBKDF2 wrapper from a UTF-8 password and salt.</summary>
    /// <inheritdoc cref="Rfc2898DeriveBytesPkcs11(Pkcs11Workspace, byte[], byte[], int, HashAlgorithmName)"/>
    public Rfc2898DeriveBytesPkcs11(Pkcs11Workspace workspace, string password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
        : this(workspace, Encoding.UTF8.GetBytes(password ?? throw new ArgumentNullException(nameof(password))),
              salt, iterations, hashAlgorithm)
    {
    }

    private static CKP PrfForHash(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => CKP.CKP_PKCS5_PBKD2_HMAC_SHA1,
        "SHA256" => CKP.CKP_PKCS5_PBKD2_HMAC_SHA256,
        "SHA384" => CKP.CKP_PKCS5_PBKD2_HMAC_SHA384,
        "SHA512" => CKP.CKP_PKCS5_PBKD2_HMAC_SHA512,
        _ => throw new NotSupportedException(
            $"PBKDF2 does not support hash {hash.Name} through this wrapper; use SHA1, SHA256, SHA384, or SHA512."),
    };

    /// <summary>
    /// Number of PBKDF2 iterations. Setting this restarts <see cref="GetBytes"/>'s byte stream from
    /// the beginning, matching the BCL.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a non-positive value.</exception>
    public int IterationCount
    {
        get => _iterationCount;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
            _iterationCount = value;
            _position = 0;
        }
    }

    /// <summary>
    /// The salt. Setting this restarts <see cref="GetBytes"/>'s byte stream from the beginning,
    /// matching the BCL.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown when set to <c>null</c>.</exception>
    public byte[] Salt
    {
        get => [.. _salt];
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _salt = [.. value];
            _position = 0;
        }
    }

    /// <summary>
    /// Resets <see cref="GetBytes"/>'s byte stream so the next call starts again from the first
    /// derived byte, matching the BCL.
    /// </summary>
    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _position = 0;
    }

    /// <summary>
    /// Returns the next <paramref name="count"/> bytes of the PBKDF2 output stream. Successive calls
    /// return successive slices of one continuous stream (matching the BCL): the concatenation of
    /// <c>GetBytes(8)</c> then <c>GetBytes(8)</c> equals a single 16-byte derivation. Call
    /// <see cref="Reset"/>, or set <see cref="Salt"/>/<see cref="IterationCount"/>, to restart the
    /// stream from the beginning.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="count"/> is not positive.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GenerateKey</c> call, or thrown when the derived bytes cannot be read back.</exception>
    /// <exception cref="InsecureOperationException">Thrown when <see cref="Pkcs11Workspace.AllowInsecure"/> is <c>false</c>: the derived value is read off the token, which the secure-defaults gate refuses by default.</exception>
    public byte[] GetBytes(int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);

        int end = _position + count;
        byte[] stream = DeriveExtractable(end);
        byte[] slice = stream[_position..end];
        CryptographicOperations.ZeroMemory(stream);
        _position = end;
        return slice;
    }

    private byte[] DeriveExtractable(int length)
    {
        var mechanism = new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params(_salt, (ulong)_iterationCount, _prf, _password));
        // Session-scoped, extractable, non-sensitive generic secret so CKA_VALUE can be read back.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(length)
            .Extractable()
            .Sensitive(false)
            .Build();

        // Public, gated path — the same one an external caller would use. The template asks for an
        // extractable, non-sensitive key, so Pkcs11Session.BuildSecureKeyDefaults refuses unless the
        // workspace has opted in. That single check is the whole policy; there is no adapter-local
        // guard to keep in step with it.
        Pkcs11Key derived = _workspace.GenerateKey(mechanism, template);
        bool operationFailed = true;
        try
        {
            using var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            if (attrs.Count == 0 || attrs[0].CannotBeRead)
                throw new InvalidOperationException(
                    "Derived key did not expose CKA_VALUE; the token may not permit reading derived key material.");
            byte[] derivedKey = attrs[0].GetValueAsByteArray();
            operationFailed = false;
            return derivedKey;
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    // See SP800108HmacCounterKdfPkcs11.DestroyEphemeral for why the destroy failure is swallowed only
    // when it would otherwise replace the real, in-flight exception.
    private static void DestroyEphemeral(Pkcs11Key derived, bool operationFailed)
    {
        using (derived)
        {
            try
            {
                derived.Destroy();
            }
            catch (Pkcs11Exception) when (operationFailed)
            {
            }
        }
    }

    /// <summary>Zeroizes the retained password and salt copies. Does not dispose the workspace.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_password);
        CryptographicOperations.ZeroMemory(_salt);
        GC.SuppressFinalize(this);
    }
}
