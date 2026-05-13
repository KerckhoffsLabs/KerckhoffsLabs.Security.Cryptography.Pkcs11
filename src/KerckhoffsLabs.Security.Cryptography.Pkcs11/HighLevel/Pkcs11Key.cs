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

    /// <summary>
    /// Returns the synthesized RSA public parameters for this key when its public side
    /// is reachable via attributes on the private-key object. Returns <c>null</c> if
    /// the key already has a real <see cref="PublicHandle"/> (caller should use that
    /// path instead), or when synthesis is unavailable (non-RSA key type, or
    /// CKA_MODULUS/CKA_PUBLIC_EXPONENT marked sensitive).
    /// </summary>
    internal System.Security.Cryptography.RSAParameters? GetSynthesizedRsaParameters()
    {
        if (_keyType != CKK.CKK_RSA) return null;
        if (!_publicHandle.IsInvalid) return null;
        if (_privateHandle.IsInvalid) return null;

        return Pkcs11PublicKeyView.TrySynthesizeRsa(_workspace.Session, _privateHandle);
    }

    /// <summary>
    /// Returns the synthesized EC public parameters when this key is an EC private-only
    /// key with readable CKA_EC_POINT + CKA_EC_PARAMS. Returns <c>null</c> when the
    /// key is non-EC, a real public handle exists (caller should use that path), or
    /// CKA_EC_POINT is sensitive/missing on the private object.
    /// </summary>
    internal System.Security.Cryptography.ECParameters? GetSynthesizedEcParameters()
    {
        if (_keyType != CKK.CKK_EC) return null;
        if (!_publicHandle.IsInvalid) return null;
        if (_privateHandle.IsInvalid) return null;
        return Pkcs11PublicKeyView.TrySynthesizeEc(_workspace.Session, _privateHandle);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        if (_ownsWorkspace) _workspace.Dispose();
        _ownedLibrary?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// One-shot factory: loads the PKCS#11 library at <paramref name="libraryPath"/>,
    /// opens an authenticated workspace, looks up the key by label, and returns it. The
    /// returned key owns the library and the workspace — disposing it tears down all
    /// three.
    /// </summary>
    /// <param name="libraryPath">Path to the PKCS#11 native library.</param>
    /// <param name="slotLabel">CKA_LABEL of the slot's token.</param>
    /// <param name="userType">User type to log in as.</param>
    /// <param name="pin">The PIN.</param>
    /// <param name="keyLabel">CKA_LABEL of the key to open.</param>
    public static Pkcs11Key Open(
        string libraryPath,
        string slotLabel,
        CKU userType,
        Security.SecurePin pin,
        string keyLabel)
    {
        ArgumentNullException.ThrowIfNull(libraryPath);
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(keyLabel);

        Pkcs11Library? library = null;
        Pkcs11Workspace? workspace = null;
        try
        {
            library = new Pkcs11Library(libraryPath);
            workspace = library.OpenWorkspace(slotLabel, userType, pin);
            return OpenKeyInternal(workspace, keyLabel, ownedLibrary: library, ownsWorkspace: true);
        }
        catch
        {
            workspace?.Dispose();
            library?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// One-shot factory taking a pre-loaded library: opens an authenticated workspace,
    /// looks up the key, and returns it. The returned key owns the workspace but NOT the
    /// library — the caller continues to own and dispose <paramref name="library"/>.
    /// </summary>
    /// <param name="library">A pre-loaded library. Caller retains ownership.</param>
    /// <param name="slotLabel">CKA_LABEL of the slot's token.</param>
    /// <param name="userType">User type to log in as.</param>
    /// <param name="pin">The PIN.</param>
    /// <param name="keyLabel">CKA_LABEL of the key to open.</param>
    public static Pkcs11Key Open(
        Pkcs11Library library,
        string slotLabel,
        CKU userType,
        Security.SecurePin pin,
        string keyLabel)
    {
        ArgumentNullException.ThrowIfNull(library);
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(keyLabel);

        Pkcs11Workspace? workspace = null;
        try
        {
            workspace = library.OpenWorkspace(slotLabel, userType, pin);
            return OpenKeyInternal(workspace, keyLabel, ownedLibrary: null, ownsWorkspace: true);
        }
        catch
        {
            workspace?.Dispose();
            throw;
        }
    }

    private static Pkcs11Key OpenKeyInternal(
        Pkcs11Workspace workspace,
        string keyLabel,
        Pkcs11Library? ownedLibrary,
        bool ownsWorkspace)
    {
        // Open the key through the workspace, then re-wrap with the ownership flags
        // appropriate for the one-shot path. We can't rebind a Pkcs11Key in place, so
        // pull the handles + metadata out of the workspace-owned key, dispose it, and
        // build a new wrapper with the ownership cascade.
        using var transient = workspace.OpenKey(keyLabel);

        var label = transient.Label;
        var idBytes = transient.Id.ToArray();
        var keyType = transient.KeyType;
        var privateHandle = transient.PrivateHandle;
        var publicHandle = transient.PublicHandle;

        return new Pkcs11Key(
            workspace,
            privateHandle,
            publicHandle,
            keyType,
            label,
            idBytes,
            ownedLibrary,
            ownsWorkspace);
    }
}
