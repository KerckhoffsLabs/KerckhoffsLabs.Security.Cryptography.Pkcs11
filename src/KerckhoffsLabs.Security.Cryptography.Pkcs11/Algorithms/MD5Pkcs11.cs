using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

// This file builds the very mechanisms the secure-by-default policy gates: it sits on the
// enforcement side of the check (the session's crypto policy check rejects them at the point of
// use unless the session's crypto policy permits it), whereas KLPKCS11009 exists to warn a *caller* who selects one.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="MD5"/> implementation backed by a PKCS#11 token's digest mechanism
/// (<c>CKM_MD5</c>), analogous to the framework's <c>MD5Cng</c>. Does NOT take ownership of the
/// supplied <see cref="Pkcs11Session"/>.
/// </summary>
/// <remarks>
/// <para>
/// MD5 is a broken hash function (practical collisions); it is provided only for interop with
/// legacy systems. Just as <c>MD5Cng</c> throws <see cref="CryptographicException"/> when the
/// Windows FIPS policy is enabled, this type is gated by the library's secure-defaults policy:
/// computing a hash throws <see cref="CryptoPolicyViolationException"/> unless the supplied
/// session's <see cref="Pkcs11Session.Policy"/> permits it (see <see cref="Pkcs11Session.UsePolicy"/>
/// to opt in for a single operation). Prefer <see cref="SHA256Pkcs11"/> or stronger.
/// </para>
/// <para>
/// PKCS#11 single-part digest is one-shot; this class buffers input written via
/// <c>HashCore</c> and issues a single <see cref="Pkcs11Session.Digest"/> on finalization
/// (see <see cref="SHA256Pkcs11"/>). The session is borrowed and not disposed.
/// </para>
/// </remarks>
[Obsolete("MD5 is a broken hash function with practical collisions. Use SHA256Pkcs11 or stronger. " +
          "MD5Pkcs11 throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
    DiagnosticId = DiagnosticIds.Md5,
    UrlFormat = DiagnosticIds.UrlFormat)]
public sealed class MD5Pkcs11 : MD5
{
    private readonly Pkcs11Session _session;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>
    /// Initialises a new PKCS#11-backed MD5 instance over <paramref name="session"/>.
    /// </summary>
    /// <param name="session">An open session whose token supports <c>CKM_MD5</c>. Borrowed,
    /// not owned — the caller remains responsible for disposing it. Computing a hash requires
    /// the session's <see cref="Pkcs11Session.Policy"/> to permit it, otherwise the
    /// secure-defaults gate throws <see cref="CryptoPolicyViolationException"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="session"/> is null.</exception>
    public MD5Pkcs11(Pkcs11Session session)
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
        var mech = new Mechanism(CKM.CKM_MD5);
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
