using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("Mock")]
public sealed class Pkcs11KeyTests
{
    private readonly MockBackendFixture _backend;
    public Pkcs11KeyTests(MockBackendFixture backend) => _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Pkcs11Key(
                workspace: null!,
                privateHandle: new ObjectHandle(1),
                publicHandle: ObjectHandle.Invalid,
                keyType: CKK.CKK_AES,
                label: null,
                id: Array.Empty<byte>(),
                ownedLibrary: null,
                ownsWorkspace: false));
    }

    [Fact]
    public void Ctor_BothHandlesInvalid_Throws()
    {
        using var workspace = OpenWorkspace();

        Assert.Throws<ArgumentException>(() =>
            new Pkcs11Key(
                workspace,
                privateHandle: ObjectHandle.Invalid,
                publicHandle: ObjectHandle.Invalid,
                keyType: CKK.CKK_AES,
                label: null,
                id: Array.Empty<byte>(),
                ownedLibrary: null,
                ownsWorkspace: false));
    }

    [Fact]
    public void Properties_AreExposed()
    {
        using var workspace = OpenWorkspace();
        byte[] id = { 0x01, 0x02 };

        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(42),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA,
            label: "my-key",
            id: id,
            ownedLibrary: null,
            ownsWorkspace: false);

        Assert.Equal(CKK.CKK_RSA, key.KeyType);
        Assert.Equal("my-key", key.Label);
        Assert.True(id.AsSpan().SequenceEqual(key.Id));

        key.Dispose();
    }

    [Fact]
    public void Dispose_NonOwningKey_DoesNotDisposeWorkspace()
    {
        using var workspace = OpenWorkspace();

        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(1),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES,
            label: null,
            id: Array.Empty<byte>(),
            ownedLibrary: null,
            ownsWorkspace: false);

        key.Dispose();
        // Re-dispose is a no-op.
        key.Dispose();

        // workspace should still be usable since key.Dispose didn't cascade.
        // Just check that workspace.GenerateRandom doesn't throw — sanity check.
        byte[] bytes = workspace.GenerateRandom(8);
        Assert.Equal(8, bytes.Length);
    }

    [Fact]
    public void Open_PathBased_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                libraryPath: null!,
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: "x"));
    }

    [Fact]
    public void Open_PathBased_NullKeyLabel_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                libraryPath: "x",
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: null!));
    }

    [Fact]
    public void Open_LibraryBased_NullLibrary_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                library: null!,
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: "x"));
    }
}
