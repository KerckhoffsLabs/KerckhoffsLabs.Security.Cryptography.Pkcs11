using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// BCL-aligned <see cref="SHA1"/> implementation backed by a PKCS#11 token's digest mechanism
/// (<c>CKM_SHA_1</c>), analogous to the framework's <c>SHA1Cng</c>. Does NOT take ownership of the
/// supplied <see cref="Pkcs11Workspace"/>.
/// </summary>
/// <remarks>
/// <para>
/// SHA-1 is broken (SHAttered demonstrated practical collisions); it is provided only for interop
/// with legacy systems. Just as <c>SHA1Cng</c> throws <see cref="CryptographicException"/> when the
/// Windows FIPS policy is enabled, this type is gated by the library's secure-defaults policy:
/// computing a hash throws <see cref="InsecureOperationException"/> unless
/// <see cref="Pkcs11Workspace.AllowInsecure"/> (or <see cref="Pkcs11Workspace.AllowInsecureScope"/>)
/// is set on the supplied workspace. Prefer <see cref="SHA256Pkcs11"/> or stronger.
/// </para>
/// <para>
/// PKCS#11 single-part digest is one-shot; this class buffers input written via
/// <c>HashCore</c> and issues a single <see cref="Pkcs11Workspace.Digest"/> on finalization
/// (see <see cref="SHA256Pkcs11"/>). The workspace is borrowed and not disposed.
/// </para>
/// </remarks>
[Obsolete("SHA-1 is broken (SHAttered demonstrated practical collisions). Use SHA256Pkcs11 or stronger. " +
          "SHA1Pkcs11 throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
public sealed class SHA1Pkcs11 : SHA1
{
    private readonly Pkcs11Workspace _workspace;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed SHA-1 instance over <paramref name="workspace"/>.
    /// </summary>
    /// <param name="workspace">An open workspace whose token supports <c>CKM_SHA_1</c>. Borrowed,
    /// not owned — the caller remains responsible for disposing it. Computing a hash requires
    /// <see cref="Pkcs11Workspace.AllowInsecure"/> to be set, otherwise the secure-defaults gate
    /// throws <see cref="InsecureOperationException"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="workspace"/> is null.</exception>
    public SHA1Pkcs11(Pkcs11Workspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        _workspace = workspace;
    }

    /// <summary>Resets the internal buffer so the instance can be reused for a new computation.</summary>
    public override void Initialize() => _buffer.SetLength(0);

    /// <inheritdoc/>
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
        => _buffer.Write(array, ibStart, cbSize);

    /// <inheritdoc/>
    protected override void HashCore(ReadOnlySpan<byte> source)
        => _buffer.Write(source);

    /// <inheritdoc/>
    protected override byte[] HashFinal()
    {
        using var mech = new Mechanism(CKM.CKM_SHA_1);
        byte[] data = _buffer.ToArray();
        _buffer.SetLength(0);
        return _workspace.Digest(mech, data);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing) _buffer.Dispose();
        base.Dispose(disposing);
    }
}
