using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// A workspace over a fake module plus keys with chosen object handles, for tests that marshal
/// key-valued mechanism parameters and assert the handle that lands in the struct. The keys are built
/// through the internal <c>Pkcs11Key</c> constructor, so no token operation is needed, and
/// <see cref="NewScope"/> binds the call scope to this workspace's session — the only session the keys
/// resolve against.
/// </summary>
internal sealed class ParameterKeys : IDisposable
{
    private readonly Pkcs11Library _library;
    private readonly bool _ownsLibrary;
    private ulong _lastSessionId;

    public ParameterKeys(ICryptoPolicy? policy = null)
        : this(new AttributeResponseModule(_ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null)).Load(), ownsLibrary: true, sessionId: 1, policy)
    {
        _lastSessionId = 1;
    }

    private ParameterKeys(Pkcs11Library library, bool ownsLibrary, ulong sessionId, ICryptoPolicy? policy)
    {
        _library = library;
        _ownsLibrary = ownsLibrary;
        var lowLevel = library.LowLevelLibrary!;
        var slot = new Pkcs11Slot(lowLevel, slotId: 1);
        var session = new Pkcs11Session(lowLevel, sessionId, policy: policy);
        Workspace = new Pkcs11Workspace(library, slot, session);
    }

    public Pkcs11Workspace Workspace { get; }

    /// <summary>
    /// Another workspace, with its own session, on the same module (only one fake module may be alive at
    /// a time), for keys that belong to a different workspace. Dispose it before this one.
    /// </summary>
    public ParameterKeys OtherWorkspace(ICryptoPolicy? policy = null)
        => new(_library, ownsLibrary: false, sessionId: ++_lastSessionId, policy);

    /// <summary>A scope for a call made on this workspace's session.</summary>
    public MechanismParameterScope NewScope() => new SessionParameterScope(Workspace.Session);

    /// <summary>A secret key whose single object has handle <paramref name="handle"/>.</summary>
    public Pkcs11Key Secret(ulong handle) => Key(handle, 0, CKK.CKK_GENERIC_SECRET);

    /// <summary>A key pair with the given private- and public-object handles.</summary>
    public Pkcs11Key Pair(ulong privateHandle, ulong publicHandle) => Key(privateHandle, publicHandle, CKK.CKK_EC_MONTGOMERY);

    /// <summary>A public key with no private half on the token.</summary>
    public Pkcs11Key PublicOnly(ulong publicHandle) => Key(0, publicHandle, CKK.CKK_EC_MONTGOMERY);

    private Pkcs11Key Key(ulong privateHandle, ulong publicHandle, CKK keyType) => new(
        Workspace,
        privateHandle: new ObjectHandle(privateHandle),
        publicHandle: new ObjectHandle(publicHandle),
        keyType: keyType,
        label: null,
        id: []);

    public void Dispose()
    {
        Workspace.Dispose();
        if (_ownsLibrary)
            _library.Dispose();
    }
}
