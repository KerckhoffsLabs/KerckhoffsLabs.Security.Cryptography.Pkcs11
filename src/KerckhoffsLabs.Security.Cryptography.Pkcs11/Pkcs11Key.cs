using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Handle wrapper over a PKCS#11 key object. Carries the workspace it belongs to, the
/// private and/or public handles, and the cached identifying metadata (label, ID, key
/// type). Mechanism-level operations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap,
/// Derive) delegate through the workspace's session.
/// </summary>
/// <remarks>
/// <para>
/// Instances are produced by <see cref="Pkcs11Workspace"/> factory methods
/// (<c>OpenKey</c>, <c>GenerateKey</c>, <c>ImportKey</c>) or by the static
/// <c>Open</c> one-shot factories. The <c>internal</c> constructor remains visible to
/// the test assembly via <c>InternalsVisibleTo</c>.
/// </para>
/// <para>
/// Asymmetric keys may carry both a private and a public handle (paired automatically
/// via <c>CKA_ID</c> by <c>Pkcs11Workspace.OpenKey</c>) or only one. A
/// public-only key has <c>privateHandle == ObjectHandle.Invalid</c>; a private-only
/// key on a token without a stored <c>CKO_PUBLIC_KEY</c> companion has
/// <c>publicHandle == ObjectHandle.Invalid</c>.
/// </para>
/// <para>
/// <b>Disposal never destroys token state.</b> <c>Dispose</c> releases the managed wrapper (and any
/// workspace or library this instance owns); <c>Destroy</c> is the only member that calls
/// <c>C_DestroyObject</c>. The two are kept apart deliberately: whether a handle refers to a
/// short-lived session object or to a persistent key is decided at creation by <c>CKA_TOKEN</c> —
/// a runtime template attribute, or the <c>persistOnToken</c> argument of the workspace factories —
/// so the wrapper cannot tell the two apart. Destroying when it should not is irreversible loss of
/// key material; failing to destroy a session object costs nothing, because PKCS#11 collects those
/// at <c>C_CloseSession</c>. Given that asymmetry, disposal stays inert and destruction stays
/// explicit.
/// </para>
/// </remarks>
public sealed class Pkcs11Key : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly Pkcs11Library? _ownedLibrary;
    private readonly bool _ownsWorkspace;
    private readonly ObjectHandle _privateHandle;
    private readonly ObjectHandle _publicHandle;
    private readonly CKK _keyType;
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
        Label = label;
        _id = id ?? [];
        _ownedLibrary = ownedLibrary;
        _ownsWorkspace = ownsWorkspace;
    }

    /// <summary>The PKCS#11 key type (e.g. <see cref="CKK.CKK_AES"/>, <see cref="CKK.CKK_RSA"/>).</summary>
    public CKK KeyType => _keyType;

    /// <summary>The key's CKA_LABEL, or <c>null</c> if not set on the token.</summary>
    public string? Label { get; }

    /// <summary>The key's CKA_ID. Returns an empty span if not set on the token.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>
    /// Returns the workspace's <see cref="Pkcs11Workspace.AllowInsecure"/> flag. Convenience accessor
    /// so consumers don't need a direct workspace reference to check the policy.
    /// </summary>
    public bool AllowInsecure => _workspace.AllowInsecure;

    /// <summary>
    /// Returns <c>true</c> when the token backing this key advertises support for the given
    /// mechanism. Convenience for adapter logic that picks between a combined-hash mechanism and a
    /// hash-then-sign fallback.
    /// </summary>
    public bool SupportsMechanism(CKM mechanism) => _workspace.Session.SupportsMechanism(mechanism);

    /// <summary>
    /// Reads the requested attribute values from this key. Uses the public-key handle for
    /// asymmetric keys when it is available (matching the rule <see cref="Encrypt"/> follows), and
    /// the private-key handle otherwise — covering both public-companion key pairs and private-only
    /// keys that carry their own attributes.
    /// </summary>
    /// <param name="types">CKA types to read.</param>
    /// <returns>The attribute values, in the same order as <paramref name="types"/>. Attributes the
    /// token does not expose come back with <see cref="ObjectAttribute.CannotBeRead"/> set.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="types"/> is null.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key exposes no readable handle; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    public IReadOnlyList<ObjectAttribute> GetAttributeValue(params CKA[] types)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(types);

        ObjectHandle handle = (IsAsymmetricKeyType(_keyType) && !_publicHandle.IsInvalid)
            ? _publicHandle
            : _privateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.GetAttributeValue (no readable handle)");

        return _workspace.Session.GetAttributeValue(handle, [.. types]);
    }

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

    /// <summary>
    /// Permanently removes the underlying object(s) from the token via <c>C_DestroyObject</c>.
    /// For a key pair this destroys both the private and public objects.
    /// </summary>
    /// <remarks>
    /// This is distinct from <see cref="Dispose"/>: <c>Dispose</c> only releases this wrapper
    /// (and any workspace/library it owns) and leaves the token object intact, whereas
    /// <c>Destroy</c> erases the key material from the token. The token enforces its own
    /// permissions — destroying a read-only object, or one created with
    /// <c>CKA_DESTROYABLE = false</c>, fails with a <see cref="Exceptions.Pkcs11Exception"/>
    /// (typically <c>CKR_ACTION_PROHIBITED</c>). After a successful destroy the handles are stale;
    /// still <see cref="Dispose"/> the key to release the wrapper.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The key has already been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DestroyObject</c> call — for example <see cref="CKR.CKR_ACTION_PROHIBITED"/> when the object is not destroyable.</exception>
    public void Destroy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_privateHandle.IsInvalid) _workspace.Session.DestroyObject(_privateHandle);
        if (!_publicHandle.IsInvalid) _workspace.Session.DestroyObject(_publicHandle);
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="libraryPath"/>, <paramref name="slotLabel"/>, <paramref name="pin"/>, or <paramref name="keyLabel"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from opening the authenticated workspace (login via <c>C_Login</c>) or from the key lookup (<c>C_FindObjects</c>).</exception>
    public static Pkcs11Key Open(
        string libraryPath,
        string slotLabel,
        CKU userType,
        SecurePin pin,
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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="library"/>, <paramref name="slotLabel"/>, <paramref name="pin"/>, or <paramref name="keyLabel"/> is <c>null</c>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from opening the authenticated workspace (login via <c>C_Login</c>) or from the key lookup (<c>C_FindObjects</c>).</exception>
    public static Pkcs11Key Open(
        Pkcs11Library library,
        string slotLabel,
        CKU userType,
        SecurePin pin,
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

    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism. Requires the key to
    /// carry a private handle (symmetric keys are sign-capable too).
    /// </summary>
    /// <param name="mechanism">The signing mechanism.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_Sign</c> call.</exception>
    public byte[] Sign(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Sign (no private handle)");

        return _workspace.Session.Sign(mechanism, _privateHandle, data);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the
    /// given mechanism. Uses the real public handle when present; falls back to managed
    /// verification via the synthesized RSA/EC public parameters when no real handle
    /// exists.
    /// </summary>
    /// <returns><c>true</c> if the signature is valid, <c>false</c> if not.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="NotSupportedException">Thrown when the managed verification fallback is taken (no public handle on the token) and <paramref name="mechanism"/> has no managed RSA/ECDSA equivalent.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no public handle exists and managed synthesis is unavailable; otherwise propagated from the underlying <c>C_Verify</c> call.</exception>
    public bool Verify(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        // Prefer the real public handle.
        if (!_publicHandle.IsInvalid)
        {
            _workspace.Session.Verify(mechanism, _publicHandle, data, signature, out bool isValid);
            return isValid;
        }

        // Fall back to managed verify via synthesized public parameters.
        if (_keyType == CKK.CKK_RSA)
        {
            var rsaParams = GetSynthesizedRsaParameters();
            if (rsaParams is not null)
                return VerifyRsaInManaged(mechanism, rsaParams.Value, data, signature);
        }
        else if (_keyType == CKK.CKK_EC)
        {
            var ecParams = GetSynthesizedEcParameters();
            if (ecParams is not null)
                return VerifyEcInManaged(mechanism, ecParams.Value, data, signature);
        }

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "Pkcs11Key.Verify (no public handle and synthesis unavailable)");
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using this key. Symmetric keys use the
    /// single handle; asymmetric public-side encryption (RSA-OAEP / RSA-PKCS) uses the
    /// public handle.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the required public or symmetric handle is unavailable; otherwise propagated from the underlying <c>C_Encrypt</c> call.</exception>
    public byte[] Encrypt(Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        ObjectHandle handle = IsAsymmetricKeyType(_keyType)
            ? _publicHandle
            : _privateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Encrypt (handle unavailable)");

        return _workspace.Session.Encrypt(mechanism, handle, plaintext);
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> using this key. Symmetric uses the single
    /// handle; asymmetric uses the private handle.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_Decrypt</c> call.</exception>
    public byte[] Decrypt(Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Decrypt (no private handle)");

        return _workspace.Session.Decrypt(mechanism, _privateHandle, ciphertext);
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD API.
    /// When false, callers should use <see cref="Encrypt"/> / <see cref="Decrypt"/>
    /// with the legacy CK_GCM_PARAMS / CK_CCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    public bool SupportsMessageApi
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _workspace.Session.SupportsMessageApi;
        }
    }

    /// <summary>
    /// One-shot AEAD encrypt using the v3.0 message-based API. The per-message tag
    /// is filled into <paramref name="messageParams"/>; read it back via the wrapper's
    /// <c>CopyTagTo</c> / <c>CopyMacTo</c> after this call.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism (mechanism parameter is empty in message mode).</param>
    /// <param name="messageParams">Per-message parameters (nonce + tag buffer).</param>
    /// <param name="associatedData">Optional AAD.</param>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <returns>Ciphertext (tag is in <paramref name="messageParams"/>).</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="messageParams"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the required public or symmetric handle is unavailable; otherwise propagated from the underlying <c>C_EncryptMessage</c> call.</exception>
    public byte[] MessageEncrypt(
        Mechanism mechanism,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        ObjectHandle handle = IsAsymmetricKeyType(_keyType) ? _publicHandle : _privateHandle;
        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.MessageEncrypt (handle unavailable)");

        return _workspace.Session.MessageEncrypt(mechanism, handle, messageParams, associatedData, plaintext);
    }

    /// <summary>
    /// One-shot AEAD decrypt using the v3.0 message-based API. Supply the tag through
    /// <paramref name="messageParams"/> constructed via its <c>ForDecrypt</c> factory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="messageParams"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_DecryptMessage</c> call — notably <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> when authentication fails.</exception>
    public byte[] MessageDecrypt(
        Mechanism mechanism,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.MessageDecrypt (no private handle)");

        return _workspace.Session.MessageDecrypt(mechanism, _privateHandle, messageParams, associatedData, ciphertext);
    }

    /// <summary>
    /// Wraps <paramref name="targetKey"/> with this key. This key is the wrapper; the
    /// target's private (or symmetric) handle is consumed by the wrap operation.
    /// </summary>
    /// <param name="mechanism">The wrap mechanism (e.g. <see cref="CKM.CKM_AES_KEY_WRAP"/>).</param>
    /// <param name="targetKey">The key being wrapped. Must carry a private/symmetric handle.</param>
    /// <returns>The wrapped key bytes — opaque blob to be transported / stored.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="targetKey"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the <see cref="AllowInsecure"/> flag is not set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when this key's wrapping handle or <paramref name="targetKey"/>'s handle is unavailable; otherwise propagated from the underlying <c>C_WrapKey</c> call.</exception>
    public byte[] Wrap(Mechanism mechanism, Pkcs11Key targetKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(targetKey);

        ObjectHandle wrapHandle = IsAsymmetricKeyType(_keyType) ? _publicHandle : _privateHandle;
        if (wrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (wrapping-key handle unavailable)");

        ObjectHandle targetHandle = targetKey._privateHandle.IsInvalid
            ? targetKey._publicHandle
            : targetKey._privateHandle;
        if (targetHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (target-key handle unavailable)");

        return _workspace.Session.WrapKey(mechanism, wrapHandle, targetHandle);
    }

    /// <summary>
    /// Unwraps the byte blob <paramref name="wrappedBytes"/> using this key as the
    /// unwrapping key, into a new on-token object described by
    /// <paramref name="template"/>.
    /// </summary>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the unwrapped object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="template"/> requests an extractable or non-sensitive key, unless the <see cref="AllowInsecure"/> flag is set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when this key's unwrapping handle is unavailable; otherwise propagated from the underlying <c>C_UnwrapKey</c> call.</exception>
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrappedBytes, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        ObjectHandle unwrapHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (unwrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Unwrap (unwrapping-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.UnwrapKey(
            mechanism, unwrapHandle, wrappedBytes, [.. template.Attributes]);

        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    /// <summary>
    /// Encapsulates a fresh shared-secret key against this key's public handle
    /// (PKCS#11 v3.2 §5.18.10). Typically used with <see cref="CKM.CKM_ML_KEM"/>.
    /// </summary>
    /// <param name="mechanism">Encapsulation mechanism.</param>
    /// <param name="sharedSecretTemplate">Template applied to the freshly-derived shared-secret key.</param>
    /// <param name="expectedCiphertextLen">
    /// When &gt; 0, the exact ciphertext length is already known (e.g. fixed by the ML-KEM parameter
    /// set), letting the token fill a pre-sized buffer in a single call instead of a NULL-buffer length
    /// probe — required for tokens (SoftHSM) that do not honour the probe for <c>C_EncapsulateKey</c>.
    /// </param>
    /// <returns>
    /// An <see cref="EncapsulationResult"/> pairing the ciphertext to send to the decapsulator with
    /// the on-token <see cref="Pkcs11Key"/> wrapping the shared secret. The caller owns the result's
    /// <see cref="EncapsulationResult.SharedSecret"/> — dispose the result (or the key) when done.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="sharedSecretTemplate"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the <see cref="AllowInsecure"/> flag is set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no public handle is reachable, or <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> from the underlying <c>C_EncapsulateKey</c> call on pre-v3.2 libraries.</exception>
    public EncapsulationResult EncapsulateKey(
        Mechanism mechanism,
        ObjectTemplate sharedSecretTemplate,
        int expectedCiphertextLen = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedSecretTemplate);

        if (_publicHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.EncapsulateKey (no public handle)");

        var (ct, sharedHandle) = _workspace.Session.EncapsulateKey(
            mechanism, _publicHandle, [.. sharedSecretTemplate.Attributes], expectedCiphertextLen);
        return new EncapsulationResult(ct, _workspace.HydrateExistingHandleAsKey(sharedHandle));
    }

    /// <summary>
    /// Decapsulates the shared-secret key from <paramref name="ciphertext"/> using this
    /// key's private handle (PKCS#11 v3.2 §5.18.11).
    /// </summary>
    /// <returns>An on-token <see cref="Pkcs11Key"/> wrapping the recovered shared secret.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="sharedSecretTemplate"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the <see cref="AllowInsecure"/> flag is set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no private handle is reachable, or <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> from the underlying <c>C_DecapsulateKey</c> call on pre-v3.2 libraries.</exception>
    public Pkcs11Key DecapsulateKey(
        Mechanism mechanism,
        ReadOnlySpan<byte> ciphertext,
        ObjectTemplate sharedSecretTemplate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedSecretTemplate);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.DecapsulateKey (no private handle)");

        ObjectHandle sharedHandle = _workspace.Session.DecapsulateKey(
            mechanism, _privateHandle, ciphertext, [.. sharedSecretTemplate.Attributes]);
        return _workspace.HydrateExistingHandleAsKey(sharedHandle);
    }

    /// <summary>
    /// Derives a new key from this key. Secure defaults (<c>CKA_SENSITIVE=true</c> /
    /// <c>CKA_EXTRACTABLE=false</c>) are applied to the result template; deriving an extractable or
    /// non-sensitive key requires opting in via the workspace's <c>AllowInsecure</c> gate.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="InsecureOperationException">Thrown if the result <paramref name="template"/> requests an extractable or non-sensitive key, or <paramref name="mechanism"/> is insecure-by-default, unless the <see cref="AllowInsecure"/> flag is set.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when this key exposes no usable base handle; otherwise propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template)
        => DeriveCore(mechanism, template);

    private Pkcs11Key DeriveCore(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        ObjectHandle baseHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (baseHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Derive (base-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.DeriveKey(
            mechanism, baseHandle, [.. template.Attributes]);
        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    private static bool IsAsymmetricKeyType(CKK keyType) => keyType switch
    {
        CKK.CKK_RSA or CKK.CKK_DSA or CKK.CKK_EC or CKK.CKK_EC_EDWARDS
            or CKK.CKK_ML_KEM or CKK.CKK_ML_DSA or CKK.CKK_SLH_DSA => true,
        _ => false,
    };

    private static bool VerifyRsaInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.RSAParameters rsaParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(rsaParams);

        var (hashName, padding) = MapRsaSignMechanism(mechanism);
        return rsa.VerifyData(data, signature, hashName, padding);
    }

    private static bool VerifyEcInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.ECParameters ecParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var ec = System.Security.Cryptography.ECDsa.Create();
        ec.ImportParameters(ecParams);

        // Raw CKM_ECDSA signs a pre-computed digest, so the input IS the hash — verify it directly.
        // The token emits an IEEE P1363 (r‖s) signature, which is ECDsa.VerifyHash's default format.
        if ((CKM)mechanism.Type == CKM.CKM_ECDSA)
            return ec.VerifyHash(data, signature);

        var hashName = MapEcdsaMechanism(mechanism);
        return ec.VerifyData(data, signature, hashName);
    }

    private static (System.Security.Cryptography.HashAlgorithmName, System.Security.Cryptography.RSASignaturePadding)
        MapRsaSignMechanism(Mechanism mechanism) => (CKM)mechanism.Type switch
        {
            CKM.CKM_SHA1_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA1, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA256_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA384_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA512_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            // PSS: RSASignaturePadding.Pss uses a digest-length salt, matching the salt the
            // RSA-PSS sign path (Pkcs11MechanismMap.RsaPssSign) defaults to.
            CKM.CKM_SHA1_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA1, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA256_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA384_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA512_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pss),
            // Raw CKM_RSA_PKCS / CKM_RSA_X_509 carry the hash inside a DigestInfo, so there is no
            // mechanism-level hash to map to a managed VerifyData call. Use a CKO_PUBLIC_KEY companion.
            _ => throw new NotSupportedException(
                $"Managed RSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };

    private static System.Security.Cryptography.HashAlgorithmName MapEcdsaMechanism(Mechanism mechanism)
        => (CKM)mechanism.Type switch
        {
            CKM.CKM_ECDSA_SHA1 => System.Security.Cryptography.HashAlgorithmName.SHA1,
            CKM.CKM_ECDSA_SHA256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
            CKM.CKM_ECDSA_SHA384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
            CKM.CKM_ECDSA_SHA512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException(
                $"Managed ECDSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };
}
