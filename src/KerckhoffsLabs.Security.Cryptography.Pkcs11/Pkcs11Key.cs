using System.Diagnostics.CodeAnalysis;
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
/// (<c>OpenKey</c>, <c>GenerateKey</c>, <c>ImportKey</c>). A key never owns its workspace or
/// library: their lifetimes stay with whoever opened them. The <c>internal</c> constructor
/// remains visible to the test assembly via <c>InternalsVisibleTo</c>.
/// </para>
/// <para>
/// Asymmetric keys may carry both a private and a public handle (paired automatically
/// via <c>CKA_ID</c> by <c>Pkcs11Workspace.OpenKey</c>) or only one. A
/// public-only key has <c>privateHandle == ObjectHandle.Invalid</c>; a private-only
/// key on a token without a stored <c>CKO_PUBLIC_KEY</c> companion has
/// <c>publicHandle == ObjectHandle.Invalid</c>.
/// </para>
/// <para>
/// <b>Disposal never destroys token state.</b> <c>Dispose</c> releases the managed wrapper only;
/// <c>Destroy</c> is the only member that calls
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
        byte[] id)
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
    }

    /// <summary>The PKCS#11 key type (e.g. <see cref="CKK.CKK_AES"/>, <see cref="CKK.CKK_RSA"/>).</summary>
    public CKK KeyType => _keyType;

    /// <summary>The key's CKA_LABEL, or <c>null</c> if not set on the token.</summary>
    public string? Label { get; }

    /// <summary>The key's CKA_ID. Returns an empty span if not set on the token.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>
    /// Returns <c>true</c> when the token backing this key advertises support for the given
    /// mechanism. Convenience for adapter logic that picks between a combined-hash mechanism and a
    /// hash-then-sign fallback. The answer is probed from the token once and cached on the session.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if another thread is currently inside an operation on the underlying session. The
    /// probe is a session operation like any other; use a separate workspace per thread.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying session has been disposed — including when the answer is already
    /// cached, since a cached capability describes a session that no longer exists.
    /// </exception>
    public bool SupportsMechanism(CKM mechanism) => _workspace.Session.SupportsMechanism(mechanism);

    /// <summary>
    /// Reads the requested attribute values from this key. Uses the public-key handle for
    /// asymmetric keys when it is available (matching the rule <see cref="Encrypt"/> follows), and
    /// the private-key handle otherwise — covering both public-companion key pairs and private-only
    /// keys that carry their own attributes.
    /// </summary>
    /// <param name="types">CKA types to read.</param>
    /// <returns>The attribute values, in the same order as <paramref name="types"/>. Attributes the
    /// token does not expose come back with <see cref="ObjectAttribute.CannotBeRead"/> set. The list
    /// owns the values: dispose it (a <c>using</c> will do) to release and zeroize their buffers.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="types"/> is null.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key exposes no readable handle; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    public ReadOnlyDisposableList<ObjectAttribute> GetAttributeValue(params CKA[] types)
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

    /// <summary>
    /// The workspace this key belongs to, and whose session and <see cref="Pkcs11Workspace.Policy"/>
    /// every operation on it goes through. The key does not own it.
    /// </summary>
    public Pkcs11Workspace Workspace => _workspace;

    /// <summary>Internal accessor for the private handle. <see cref="ObjectHandle.Invalid"/> for public-only keys.</summary>
    internal ObjectHandle PrivateHandle => _privateHandle;

    /// <summary>Internal accessor for the public handle. <see cref="ObjectHandle.Invalid"/> when no companion exists and synthesis is unavailable.</summary>
    internal ObjectHandle PublicHandle => _publicHandle;

    /// <summary>
    /// Checks that this key has the token object a mechanism parameter asks for, so a parameter type
    /// can reject an unusable key when it is constructed rather than when the operation runs.
    /// </summary>
    /// <param name="part">Which object the parameter refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ArgumentException">The key has no object of that kind — for example a public
    /// part requested from a secret key, or a private part from a public-only key.</exception>
    internal void EnsureHasParameterHandle(KeyHandlePart part, string paramName) =>
        _ = SelectParameterHandle(part, paramName);

    /// <summary>
    /// Resolves the handle a mechanism parameter carries for this key, at the moment the parameter is
    /// marshalled for <paramref name="session"/>.
    /// </summary>
    /// <remarks>
    /// A handle only means something to the session and login it came from, so a key from another
    /// workspace is refused rather than sent: its number could name an unrelated object — or nothing —
    /// in the calling session.
    /// </remarks>
    /// <param name="session">The session performing the call.</param>
    /// <param name="part">Which object the parameter refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    /// <exception cref="ArgumentException">The key belongs to a different workspace, or has no object
    /// of the requested kind.</exception>
    internal ObjectHandle ResolveParameterHandle(Pkcs11Session session, KeyHandlePart part, string paramName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!ReferenceEquals(_workspace.Session, session))
            throw new ArgumentException(
                "The key belongs to a different workspace than the operation. Mechanism parameters can only " +
                "reference keys from the workspace that performs the call.",
                paramName);
        return SelectParameterHandle(part, paramName);
    }

    private ObjectHandle SelectParameterHandle(KeyHandlePart part, string paramName)
    {
        switch (part)
        {
            case KeyHandlePart.Private:
                if (_privateHandle.IsInvalid)
                    throw new ArgumentException(
                        "The key has no private-key or secret-key object on the token; this parameter needs one.",
                        paramName);
                return _privateHandle;

            case KeyHandlePart.Public:
                if (_publicHandle.IsInvalid)
                    throw new ArgumentException(
                        "The key has no public-key object on the token (a secret key never has one); this " +
                        "parameter needs one.",
                        paramName);
                return _publicHandle;

            default:
                throw new ArgumentOutOfRangeException(nameof(part), part, "Not a defined KeyHandlePart member.");
        }
    }

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
    /// and leaves the token object intact, whereas
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
        _disposed = true;
        GC.SuppressFinalize(this);
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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

        // Fall back to managed verify via synthesized public parameters. No session call happens on this
        // path, so the workspace policy is consulted here — the same verdict the token path gets from
        // the session's own check.
        _workspace.Session.Enforce(new MechanismUseRequest(mechanism, CryptoOperation.Verify));

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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses it.</exception>
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
    /// <paramref name="template"/>. Symmetric uses the single handle; asymmetric
    /// uses the private handle (unwrapping is a decrypt-shaped operation).
    /// </summary>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the unwrapped object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="template"/> requests an extractable or non-sensitive key, unless the workspace's <see cref="Pkcs11Workspace.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_UnwrapKey</c> call.</exception>
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrappedBytes, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Unwrap (no private handle)");

        ObjectHandle resulting = _workspace.Session.UnwrapKey(
            mechanism, _privateHandle, wrappedBytes, [.. template.Attributes]);

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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the workspace's <see cref="Pkcs11Workspace.Policy"/> permits it.</exception>
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
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the workspace's <see cref="Pkcs11Workspace.Policy"/> permits it.</exception>
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
    /// non-sensitive key is refused by <c>CryptoPolicy.SecureOnly</c>: to read a derived secret back, use
    /// <see cref="DeriveAndExportSecret"/>, which the policy decides as a narrow key-material export. Symmetric
    /// uses the single handle; asymmetric uses the private handle (e.g. ECDH derives from the
    /// local private key — the peer's public point travels as a mechanism parameter, not a handle).
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown for <c>CKM_ECDH1_DERIVE</c> / <c>CKM_ECDH1_COFACTOR_DERIVE</c> from a <see cref="CKK.CKK_EC"/> key on a catalog curve when the peer in <see cref="CkmEcdh1DeriveParams"/> names another curve, is not an uncompressed point of the key's curve, or does not satisfy the curve equation; also for <c>CKM_HKDF_DATA</c>, which creates a data object rather than a key.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the result <paramref name="template"/> requests an extractable or non-sensitive key, or <paramref name="mechanism"/> is insecure-by-default, unless the workspace's <see cref="Pkcs11Workspace.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template)
        => DeriveCore(mechanism, template, nameof(mechanism));

    /// <summary><see cref="Derive"/>, reporting an invalid ECDH peer against <paramref name="peerParamName"/>.</summary>
    internal Pkcs11Key DeriveCore(Mechanism mechanism, ObjectTemplate template, string peerParamName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Derive (no private handle)");

        ObjectHandle resulting = _workspace.Session.DeriveKey(
            mechanism, _privateHandle, [.. template.Attributes], peerParamName: peerParamName);

        // SP800-108 sibling keys: the params object absorbed their raw handles during the call
        // above; turn them into usable Pkcs11Key instances now, while the workspace is at hand.
        if (mechanism.Parameters is CkmSp800108KdfParams sp800108)
            sp800108.HydrateDerivedKeys(_workspace);

        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    /// <summary>
    /// Returns this EC key's named curve, read from its <c>CKA_EC_PARAMS</c>.
    /// </summary>
    /// <returns>The curve. <see cref="Pkcs11ECCurve.FieldSizeBits"/> is set for every curve in the library's catalog.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="KeyType"/> is not <see cref="CKK.CKK_EC"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose <c>CKA_EC_PARAMS</c>, or its value is not a DER-encoded named-curve OID.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11ECCurve GetEcCurve()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireEcKey();

        using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs[0].CannotBeRead)
            throw new System.Security.Cryptography.CryptographicException("The token does not expose this key's CKA_EC_PARAMS.");
        try
        {
            return Pkcs11ECCurve.FromEcParams(attrs[0].GetValueAsByteArray());
        }
        catch (ArgumentException ex)
        {
            throw new System.Security.Cryptography.CryptographicException("This key's CKA_EC_PARAMS is not a DER-encoded named-curve OID.", ex);
        }
    }

    /// <summary>
    /// Returns this EC key's public key — its named curve and uncompressed point — read from
    /// <c>CKA_EC_PARAMS</c> and <c>CKA_EC_POINT</c>. Reads the public object when the key has one, the
    /// private object otherwise; PKCS#11 does not require a private key to carry <c>CKA_EC_POINT</c>.
    /// </summary>
    /// <returns>Public parameters only; <see cref="System.Security.Cryptography.ECParameters.D"/> is never set.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="KeyType"/> is not <see cref="CKK.CKK_EC"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose <c>CKA_EC_POINT</c> or <c>CKA_EC_PARAMS</c>, or they do not decode as a named curve and an uncompressed point.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    public System.Security.Cryptography.ECParameters ExportEcPublicParameters()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireEcKey();

        using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(CKA.CKA_EC_POINT, CKA.CKA_EC_PARAMS);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            throw new System.Security.Cryptography.CryptographicException(
                "The token does not expose this key's CKA_EC_POINT and CKA_EC_PARAMS.");
        return Pkcs11PublicKeyView.TryParseEcPublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray())
            ?? throw new System.Security.Cryptography.CryptographicException(
                "This key's CKA_EC_POINT / CKA_EC_PARAMS do not decode as a named curve and an uncompressed point.");
    }

    private void RequireEcKey()
    {
        if (_keyType != CKK.CKK_EC)
            throw new InvalidOperationException($"This is a {_keyType} key, not an EC key.");
    }

    /// <summary>
    /// Derives a secret from this key on the token and copies it into <paramref name="destination"/>.
    /// For a protocol whose next step runs in managed code — a BCL-shaped KDF, a TLS or Noise key
    /// schedule — and so needs the bytes rather than a key that stays on the token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This exports key material.</b> The workspace's <see cref="Pkcs11Workspace.Policy"/> decides it
    /// as a <see cref="KeyMaterialExportRequest"/>, which <c>CryptoPolicy.SecureOnly</c> refuses unless
    /// widened for that one kind, e.g.
    /// <c>CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, reason)</c>.
    /// When the secret can stay on the token, use <see cref="Derive"/> with a sensitive template instead;
    /// nothing is exported and no opt-in is needed.
    /// </para>
    /// <para>
    /// The mechanisms are a closed list, and the kind of export follows from the mechanism:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>CKM_ECDH1_DERIVE</c> / <c>CKM_ECDH1_COFACTOR_DERIVE</c> with
    /// <see cref="CkmEcdh1DeriveParams"/> naming a peer point (e.g. from
    /// <see cref="CkmEcdh1DeriveParams.ForPeer"/>) — <see cref="KeyMaterialExportKind.EcdhSharedSecret"/>,
    /// whatever the KDF. The key must be a <see cref="CKK.CKK_EC"/> key, and the peer point is checked
    /// against its curve before it reaches the token. With <c>CKD_NULL</c> the result is the raw shared
    /// secret Z, and <paramref name="destination"/> must be exactly the curve's field size
    /// (<see cref="GetEcCurve"/>), so Z is never silently truncated.</description></item>
    /// <item><description><c>CKM_HKDF_DERIVE</c> with <see cref="CkmHkdfParams"/> —
    /// <see cref="KeyMaterialExportKind.KdfOutput"/>.</description></item>
    /// <item><description><c>CKM_SP800_108_COUNTER_KDF</c>, <c>_FEEDBACK_KDF</c> and
    /// <c>_DOUBLE_PIPELINE_KDF</c> with <see cref="CkmSp800108KdfParams"/> that derive no additional keys —
    /// <see cref="KeyMaterialExportKind.KdfOutput"/>.</description></item>
    /// </list>
    /// <para>
    /// Any other mechanism is refused, whatever the policy: several derivation mechanisms
    /// (<c>CKM_XOR_BASE_AND_DATA</c>, <c>CKM_CONCATENATE_BASE_AND_KEY</c>, <c>CKM_EXTRACT_KEY_FROM_KEY</c>,
    /// <c>CKM_AES_ECB_ENCRYPT_DATA</c>, …) would return the base key itself, or an encryption of it.
    /// </para>
    /// <para>
    /// The secret passes through an ephemeral session key the library creates — generic secret,
    /// extractable, not sensitive, not copyable, no usage — and destroys before this
    /// returns, whether it succeeds or not. That template is covered by the export decision and not
    /// judged again as a key template; for ECDH with <c>CKD_NULL</c>, neither is the key-agreement KDF.
    /// The mechanism is still judged. On failure, <paramref name="destination"/> is zeroed.
    /// </para>
    /// </remarks>
    /// <param name="mechanism">One of the mechanisms listed in the remarks.</param>
    /// <param name="destination">Receives the secret; its length is the length derived.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is empty; if <paramref name="mechanism"/> is not one of the supported shapes; or, for ECDH, if the key is not a <see cref="CKK.CKK_EC"/> key, the peer names another curve or its point is not an uncompressed point on the key's curve, or, with <c>CKD_NULL</c>, <paramref name="destination"/> is not the curve's field size.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the key has no private or secret handle to derive from.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses the export or the mechanism.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose the derived value or produces one of another length, or, for ECDH, if the key's curve cannot be read.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DeriveKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c> call.</exception>
    public void DeriveAndExportSecret(Mechanism mechanism, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        RequireNonEmpty(destination, nameof(destination));
        KeyMaterialExportKind kind = SecretExport.Classify(SecretExport.Operation.Derive, mechanism, nameof(mechanism));
        if (_privateHandle.IsInvalid)
            throw new InvalidOperationException("This key has no private or secret handle to derive from.");
        if (kind == KeyMaterialExportKind.EcdhSharedSecret)
            RequireRawSecretLength((CkmEcdh1DeriveParams)mechanism.Parameters!, destination.Length);

        Pkcs11Session session = _workspace.Session;
        SecretExport.Authorize(session, kind, mechanism.Type, IsAsymmetricKeyType(_keyType) ? CKO.CKO_PRIVATE_KEY : CKO.CKO_SECRET_KEY, _keyType);
        // The session checks an ECDH peer against this key's curve, and refuses an ECDH export from a
        // key that is not CKK_EC.
        SecretExport.Export(session, destination.Length,
            template => session.DeriveKey(mechanism, _privateHandle, template, kind),
            destination);
    }

    // The raw ECDH secret Z is one field element; a shorter destination would silently truncate it.
    // Other key types are refused by the session, and a curve outside the catalog has no known size.
    private void RequireRawSecretLength(CkmEcdh1DeriveParams parameters, int length)
    {
        if (parameters.Kdf != CKD.CKD_NULL || _keyType != CKK.CKK_EC || GetEcCurve().FieldSizeBits is not int bits)
            return;
        int fieldSize = (bits + 7) / 8;
        if (length != fieldSize)
            throw new ArgumentException(
                $"The raw ECDH shared secret on this curve is {fieldSize} bytes; the destination is {length}.",
                "destination");
    }

    /// <summary>
    /// Encapsulates a fresh shared secret against this key's public half (PKCS#11 v3.2 §5.18.10) and
    /// copies both the ciphertext and the shared secret out. For a protocol that needs the secret's
    /// bytes, such as a hybrid key exchange feeding a managed KDF.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This exports key material</b>, decided as a <see cref="KeyMaterialExportRequest"/> of
    /// <see cref="KeyMaterialExportKind.KemSharedSecret"/>, which <c>CryptoPolicy.SecureOnly</c> refuses
    /// unless widened for it. When the secret can stay on the token, use <see cref="EncapsulateKey"/>.
    /// Only <c>CKM_ML_KEM</c> is supported. The secret passes through an ephemeral session key that is
    /// destroyed before this returns; on failure, <paramref name="sharedSecret"/> is zeroed.
    /// </para>
    /// </remarks>
    /// <param name="mechanism"><c>CKM_ML_KEM</c>.</param>
    /// <param name="ciphertext">Receives the ciphertext. Must be at least the parameter set's ciphertext size (768, 1088 or 1568 bytes); the token is handed the whole buffer in one call.</param>
    /// <param name="sharedSecret">Receives the shared secret; for ML-KEM, 32 bytes.</param>
    /// <returns>The number of bytes written to <paramref name="ciphertext"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="ciphertext"/> or <paramref name="sharedSecret"/> is empty, or <paramref name="mechanism"/> is not <c>CKM_ML_KEM</c>.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the key has no public handle.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses the export or the mechanism.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose the shared secret or produces one of another length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_EncapsulateKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c> call — <see cref="CKR.CKR_BUFFER_TOO_SMALL"/> when <paramref name="ciphertext"/> is too short.</exception>
    [Experimental(DiagnosticIds.ExperimentalKem, UrlFormat = DiagnosticIds.UrlFormat)]
    public int EncapsulateAndExportSecret(Mechanism mechanism, Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        RequireNonEmpty(ciphertext, nameof(ciphertext));
        RequireNonEmpty(sharedSecret, nameof(sharedSecret));
        KeyMaterialExportKind kind = SecretExport.Classify(SecretExport.Operation.Encapsulate, mechanism, nameof(mechanism));
        if (_publicHandle.IsInvalid)
            throw new InvalidOperationException("This key has no public handle to encapsulate against.");

        Pkcs11Session session = _workspace.Session;
        SecretExport.Authorize(session, kind, mechanism.Type, CKO.CKO_PUBLIC_KEY, _keyType);

        int ciphertextCapacity = ciphertext.Length;
        byte[] ct = [];
        SecretExport.Export(session, sharedSecret.Length, template =>
        {
            (ct, ObjectHandle ephemeral) = session.EncapsulateKey(mechanism, _publicHandle, template, ciphertextCapacity, kind);
            return ephemeral;
        }, sharedSecret);
        // The token wrote into a buffer of ciphertext.Length and reports what it used, so this fits.
        ct.CopyTo(ciphertext);
        return ct.Length;
    }

    /// <summary>
    /// Decapsulates the shared secret from <paramref name="ciphertext"/> with this key's private half
    /// (PKCS#11 v3.2 §5.18.11) and copies it into <paramref name="sharedSecret"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This exports key material</b>, decided as a <see cref="KeyMaterialExportRequest"/> of
    /// <see cref="KeyMaterialExportKind.KemSharedSecret"/>, which <c>CryptoPolicy.SecureOnly</c> refuses
    /// unless widened for it. When the secret can stay on the token, use <see cref="DecapsulateKey"/>.
    /// Only <c>CKM_ML_KEM</c> is supported: the KEM entry points also accept RSA PKCS#1 v1.5, whose
    /// decapsulated output must never be handed back. The secret passes through an ephemeral session
    /// key that is destroyed before this returns; on failure, <paramref name="sharedSecret"/> is zeroed.
    /// </para>
    /// <para>
    /// Tokens disagree on whether the ephemeral key's template may carry <c>CKA_VALUE_LEN</c> here
    /// (opencryptoki requires it, SoftHSM refuses it as read-only). The first call against a library
    /// finds out, and the answer is remembered for that library.
    /// </para>
    /// </remarks>
    /// <param name="mechanism"><c>CKM_ML_KEM</c>.</param>
    /// <param name="ciphertext">The ciphertext produced by the encapsulating party.</param>
    /// <param name="sharedSecret">Receives the shared secret; for ML-KEM, 32 bytes.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="sharedSecret"/> is empty, or <paramref name="mechanism"/> is not <c>CKM_ML_KEM</c>.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the key has no private handle.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the workspace's <see cref="Pkcs11Workspace.Policy"/> refuses the export or the mechanism.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the token does not expose the shared secret or produces one of another length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DecapsulateKey</c>, <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c> call.</exception>
    [Experimental(DiagnosticIds.ExperimentalKem, UrlFormat = DiagnosticIds.UrlFormat)]
    public void DecapsulateAndExportSecret(Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        RequireNonEmpty(sharedSecret, nameof(sharedSecret));
        KeyMaterialExportKind kind = SecretExport.Classify(SecretExport.Operation.Decapsulate, mechanism, nameof(mechanism));
        if (_privateHandle.IsInvalid)
            throw new InvalidOperationException("This key has no private handle to decapsulate with.");

        Pkcs11Session session = _workspace.Session;
        SecretExport.Authorize(session, kind, mechanism.Type, CKO.CKO_PRIVATE_KEY, _keyType);

        // Tokens disagree on CKA_VALUE_LEN here (see the remarks). The first call against a library tries
        // the conventional template and falls back on SoftHSM's read-only refusal, which creates nothing;
        // the form that worked is remembered on the library, so later calls go straight to it.
        byte[] ct = ciphertext.ToArray();
        Pkcs11Library library = _workspace.Library;
        if (library.MlKemDecapsulateOmitsValueLen is bool omit)
        {
            ExportDecapsulated(session, mechanism, ct, omit ? null : sharedSecret.Length, kind, sharedSecret);
            return;
        }

        try
        {
            ExportDecapsulated(session, mechanism, ct, sharedSecret.Length, kind, sharedSecret);
            library.MlKemDecapsulateOmitsValueLen = false;
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            ExportDecapsulated(session, mechanism, ct, null, kind, sharedSecret);
            library.MlKemDecapsulateOmitsValueLen = true;
        }
    }

    private void ExportDecapsulated(
        Pkcs11Session session, Mechanism mechanism, byte[] ciphertext, int? valueLength, KeyMaterialExportKind kind, Span<byte> sharedSecret)
        => SecretExport.Export(session, valueLength,
            template => session.DecapsulateKey(mechanism, _privateHandle, ciphertext, template, kind),
            sharedSecret);

    private static void RequireNonEmpty(ReadOnlySpan<byte> buffer, string paramName)
    {
        if (buffer.IsEmpty)
            throw new ArgumentException("The buffer must not be empty.", paramName);
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
        if (mechanism.Type == CKM.CKM_ECDSA)
            return ec.VerifyHash(data, signature);

        var hashName = MapEcdsaMechanism(mechanism);
        return ec.VerifyData(data, signature, hashName);
    }

    private static (System.Security.Cryptography.HashAlgorithmName, System.Security.Cryptography.RSASignaturePadding)
        MapRsaSignMechanism(Mechanism mechanism) => mechanism.Type switch
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
        => mechanism.Type switch
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
