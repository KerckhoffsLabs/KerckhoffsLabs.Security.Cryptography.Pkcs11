using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// Builds a <c>Pkcs11Key</c> directly over an <see cref="AttributeResponseModule"/>, using the
/// internal <c>Pkcs11Slot</c>/<c>Pkcs11Session</c>/<c>Pkcs11Key</c> constructors (visible to this
/// assembly via <c>InternalsVisibleTo</c>) rather than the usual open-session/generate-key-pair flow.
/// Lets a test drive an exact, otherwise unreachable <c>C_GetAttributeValue</c> response — a real
/// token's required key attributes (e.g. RSA's <c>CKA_MODULUS</c>, DSA's <c>CKA_PRIME</c>) can't be
/// made unreadable or fatally erroring on a well-formed key object, which is what the adapters'
/// key-size fallback paths need to see.
/// </summary>
internal static class FakeKeys
{
    public static FakeKey Create(CKK keyType, Func<CKA, (CKR Rv, byte[]? Value)> respond, ICryptoPolicy? policy = null)
    {
        var library = new AttributeResponseModule(respond).Load();
        var lowLevel = library.LowLevelLibrary!;
        var slot = new Pkcs11Slot(lowLevel, slotId: 1);
        var session = new Pkcs11Session(lowLevel, sessionId: 1, policy: policy);
        var workspace = new Pkcs11Workspace(library, slot, session);
        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(1),
            publicHandle: ObjectHandle.Invalid,
            keyType: keyType,
            label: null,
            id: []);
        return new FakeKey(key, workspace, library);
    }
}

/// <summary>
/// A key from <see cref="FakeKeys.Create"/> together with the workspace and library behind it. A key
/// never owns its workspace or library, so disposing this disposes all three: the library releases the
/// fake module, which must happen before the next test loads one. It converts to the
/// <see cref="Pkcs11Key"/> it carries.
/// </summary>
internal sealed class FakeKey(Pkcs11Key key, Pkcs11Workspace workspace, Pkcs11Library library) : IDisposable
{
    public Pkcs11Key Key { get; } = key;

    public static implicit operator Pkcs11Key(FakeKey fake) => fake.Key;

    public void Dispose()
    {
        Key.Dispose();
        workspace.Dispose();
        library.Dispose();
    }
}
