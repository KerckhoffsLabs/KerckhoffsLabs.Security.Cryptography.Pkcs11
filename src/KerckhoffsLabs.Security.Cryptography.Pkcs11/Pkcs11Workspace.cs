using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Authenticated context against a PKCS#11 token. Holds the library, slot, and active
/// session and exposes the operations a caller performs while logged in.
/// </summary>
/// <remarks>
/// <para>
/// Construction is exclusively via <see cref="Pkcs11Library.OpenWorkspace(string, CKU, SecurePin)"/>.
/// The workspace does not own the library — callers continue to own and dispose the
/// <see cref="Pkcs11Library"/>. The workspace owns the session it opened and closes it
/// on <see cref="Dispose"/>; the session's own Dispose logs the user out before closing.
/// </para>
/// <para>
/// Keys obtained via the workspace's factory methods hold a non-owning reference to the
/// workspace. The workspace must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Workspace : IDisposable
{
    private readonly Pkcs11Library _library;
    private readonly Pkcs11Slot _slot;
    private readonly Pkcs11Session _session;
    private bool _disposed;

    internal Pkcs11Workspace(Pkcs11Library library, Pkcs11Slot slot, Pkcs11Session session)
    {
        _library = library;
        _slot = slot;
        _session = session;
    }

    /// <summary>The slot this workspace is authenticated against.</summary>
    public Pkcs11Slot Slot => _slot;

    /// <summary>The library that hosts this workspace. The workspace does not own the library.</summary>
    public Pkcs11Library Library => _library;

    /// <summary>Internal accessor for the underlying session. Used by <c>Pkcs11Key</c> to delegate operations.</summary>
    internal Pkcs11Session Session => _session;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _session.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
