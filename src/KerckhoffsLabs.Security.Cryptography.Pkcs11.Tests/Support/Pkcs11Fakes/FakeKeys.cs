using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// Builds a <c>Pkcs11Key</c> directly over an <see cref="AttributeResponseFakeLibrary"/>, using the
/// internal <c>Pkcs11Library</c>/<c>Pkcs11Slot</c>/<c>Pkcs11Session</c>/<c>Pkcs11Key</c> constructors
/// (visible to this assembly via <c>InternalsVisibleTo</c>) rather than the usual open-session/
/// generate-key-pair flow. Lets a test drive an exact, otherwise unreachable
/// <c>C_GetAttributeValue</c> response — a real token's required key attributes (e.g. RSA's
/// <c>CKA_MODULUS</c>, DSA's <c>CKA_PRIME</c>) can't be made unreadable or fatally erroring on a
/// well-formed key object, which is what the adapters' key-size fallback paths need to see.
/// </summary>
internal static class FakeKeys
{
    public static Pkcs11Key Create(CKK keyType, Func<CKA, (CKR Rv, byte[]? Value)> respond)
    {
        var lowLevel = new AttributeResponseFakeLibrary(respond);
        var library = new Pkcs11Library(lowLevel);
        var slot = new Pkcs11Slot(lowLevel, slotId: 1);
        var session = new Pkcs11Session(lowLevel, sessionId: 1);
        var workspace = new Pkcs11Workspace(library, slot, session);
        return new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(1),
            publicHandle: ObjectHandle.Invalid,
            keyType: keyType,
            label: null,
            id: [],
            ownedLibrary: library,
            ownsWorkspace: true);
    }
}
