using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Handle wrapper over a PKCS#11 key object. Carries the workspace it belongs to, the
/// private and/or public handles, and the cached identifying metadata (label, ID, key
/// type). Operations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap, Derive) live on a
/// partial file (<c>Pkcs11Key.Mechanism.cs</c>) and delegate through the workspace's
/// session.
/// </summary>
/// <remarks>
/// <para>
/// Instances are produced by <see cref="Pkcs11Workspace"/> factory methods
/// (<c>OpenKey</c>, <c>GenerateKey</c>, <c>ImportKey</c>) or by the static
/// <c>Open</c> one-shot factories. The <c>internal</c> constructor remains visible to
/// the test assembly via <c>InternalsVisibleTo</c>.
/// </para>
/// <para>
/// Disposing a key releases owned resources (workspace and/or library, depending on how
/// the key was constructed). It does NOT destroy the underlying PKCS#11 object on the
/// token; handles refer to token-side state that may legitimately outlive the wrapper.
/// </para>
/// <para>
/// Asymmetric keys may carry both a private and a public handle (paired automatically
/// via <c>CKA_ID</c> by <c>Pkcs11Workspace.OpenKey</c>) or only one. A
/// public-only key has <c>privateHandle == ObjectHandle.Invalid</c>; a private-only
/// key on a token without a stored <c>CKO_PUBLIC_KEY</c> companion has
/// <c>publicHandle == ObjectHandle.Invalid</c>.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Key : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly Pkcs11Library? _ownedLibrary;
    private readonly bool _ownsWorkspace;
    private readonly ObjectHandle _privateHandle;
    private readonly ObjectHandle _publicHandle;
    private readonly CKK _keyType;
    private readonly string? _label;
    private readonly byte[] _id;
    private bool _disposed;

    internal Pkcs11Key(
        Pkcs11Workspace workspace,
        ObjectHandle privateHandle,
        ObjectHandle publicHandle,
        CKK keyType,
        string? label,
        byte[] id,
        Pkcs11Library? ownedLibrary,
        bool ownsWorkspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        if (privateHandle.IsInvalid && publicHandle.IsInvalid)
            throw new ArgumentException(
                "Pkcs11Key must carry at least one valid handle.",
                nameof(privateHandle));

        _workspace = workspace;
        _privateHandle = privateHandle;
        _publicHandle = publicHandle;
        _keyType = keyType;
        _label = label;
        _id = id ?? Array.Empty<byte>();
        _ownedLibrary = ownedLibrary;
        _ownsWorkspace = ownsWorkspace;
    }

    /// <summary>The PKCS#11 key type (e.g. <see cref="CKK.CKK_AES"/>, <see cref="CKK.CKK_RSA"/>).</summary>
    public CKK KeyType => _keyType;

    /// <summary>The key's CKA_LABEL, or <c>null</c> if not set on the token.</summary>
    public string? Label => _label;

    /// <summary>The key's CKA_ID. Returns an empty span if not set on the token.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>Internal accessor for the workspace this key belongs to.</summary>
    internal Pkcs11Workspace Workspace => _workspace;

    /// <summary>Internal accessor for the private handle. <see cref="ObjectHandle.Invalid"/> for public-only keys.</summary>
    internal ObjectHandle PrivateHandle => _privateHandle;

    /// <summary>Internal accessor for the public handle. <see cref="ObjectHandle.Invalid"/> when no companion exists and synthesis is unavailable.</summary>
    internal ObjectHandle PublicHandle => _publicHandle;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        if (_ownsWorkspace) _workspace.Dispose();
        _ownedLibrary?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
