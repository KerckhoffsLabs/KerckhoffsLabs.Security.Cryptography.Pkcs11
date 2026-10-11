using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="SHA384"/> implementation backed by a PKCS#11 token's digest mechanism
/// (<c>CKM_SHA384</c>), analogous to the framework's <c>SHA384Cng</c>. Does NOT take ownership of
/// the supplied <see cref="Pkcs11Session"/>. See <see cref="SHA256Pkcs11"/> for the buffering
/// rationale (PKCS#11 single-part digest is one-shot).
/// </summary>
public sealed class SHA384Pkcs11 : SHA384
{
    private readonly Pkcs11Session _session;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed SHA-384 instance over <paramref name="session"/>.
    /// </summary>
    /// <param name="session">An open session whose token supports <c>CKM_SHA384</c>. Borrowed,
    /// not owned — the caller remains responsible for disposing it.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="session"/> is null.</exception>
    public SHA384Pkcs11(Pkcs11Session session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
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
        var mech = new Mechanism(CKM.CKM_SHA384);
        byte[] data = _buffer.ToArray();
        _buffer.SetLength(0);
        return _session.Digest(mech, data);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing) _buffer.Dispose();
        base.Dispose(disposing);
    }
}
