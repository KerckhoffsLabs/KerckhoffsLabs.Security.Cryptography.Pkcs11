using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="SHA3_384"/> implementation backed by a PKCS#11 token's digest mechanism
/// (<c>CKM_SHA3_384</c>). Hashing happens on the token rather than in managed code. Does NOT take
/// ownership of the supplied <see cref="Pkcs11Workspace"/>.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 single-part digest is one-shot (<c>C_DigestInit</c> + <c>C_Digest</c>); this class bridges
/// the BCL's streaming <see cref="HashAlgorithm.HashCore(byte[], int, int)"/> / <see cref="HashAlgorithm.HashFinal"/>
/// contract by buffering everything written and issuing a single <see cref="Pkcs11Workspace.Digest"/>
/// on finalization (mirrors <see cref="SHA3_256Pkcs11"/>).
/// </para>
/// <para>
/// SHA3-384 (FIPS 202) is a secure hash and is not gated by the secure-defaults policy. The token must
/// implement <c>CKM_SHA3_384</c> — not all do (SoftHSM, for example, does not). Memory usage grows
/// linearly with accumulated input; the workspace is borrowed and not disposed.
/// </para>
/// </remarks>
public sealed class SHA3_384Pkcs11 : SHA3_384
{
    private readonly Pkcs11Workspace _workspace;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed SHA3-384 instance over <paramref name="workspace"/>.
    /// </summary>
    /// <param name="workspace">An open workspace whose token supports <c>CKM_SHA3_384</c>. Borrowed,
    /// not owned — the caller remains responsible for disposing it.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="workspace"/> is null.</exception>
    public SHA3_384Pkcs11(Pkcs11Workspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        _workspace = workspace;
        // SHA3_384's base constructor already fixes HashSizeValue at 384.
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
        var mech = new Mechanism(CKM.CKM_SHA3_384);
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
