using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="SHA256"/> implementation backed by a PKCS#11 token's digest mechanism
/// (<c>CKM_SHA256</c>), analogous to the framework's <c>SHA256Cng</c> (which is backed by Windows
/// CNG). Hashing happens on the token rather than in managed code. Does NOT take ownership of the
/// supplied <see cref="Pkcs11Workspace"/>.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 single-part digest is one-shot (<c>C_DigestInit</c> + <c>C_Digest</c>); there is no
/// portable streaming digest in the BCL-mappable surface here. This class bridges the BCL's
/// streaming <see cref="HashAlgorithm.HashCore(byte[], int, int)"/> / <see cref="HashAlgorithm.HashFinal"/>
/// contract by buffering everything written and issuing a single <see cref="Pkcs11Workspace.Digest"/>
/// on finalization.
/// </para>
/// <para>
/// Memory usage grows linearly with accumulated input — fine for typical message hashing; for
/// multi-gigabyte streams prefer a software SHA-256. The workspace is borrowed and not disposed.
/// </para>
/// </remarks>
public sealed class SHA256Pkcs11 : SHA256
{
    private readonly Pkcs11Workspace _workspace;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed SHA-256 instance over <paramref name="workspace"/>.
    /// </summary>
    /// <param name="workspace">An open workspace whose token supports <c>CKM_SHA256</c>. Borrowed,
    /// not owned — the caller remains responsible for disposing it.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="workspace"/> is null.</exception>
    public SHA256Pkcs11(Pkcs11Workspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        _workspace = workspace;
        // SHA256's base constructor already fixes HashSizeValue at 256.
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
        using var mech = new Mechanism(CKM.CKM_SHA256);
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
