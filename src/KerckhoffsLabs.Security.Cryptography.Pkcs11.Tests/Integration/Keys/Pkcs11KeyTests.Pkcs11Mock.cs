using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Mock")]
public sealed class Pkcs11KeyTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithPin(
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
                id: []));
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
                id: []));
    }

    [Fact]
    public void Properties_AreExposed()
    {
        using var workspace = OpenWorkspace();
        byte[] id = [0x01, 0x02];

        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(42),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA,
            label: "my-key",
            id: id);

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
            id: []);

        key.Dispose();
        // Re-dispose is a no-op.
        key.Dispose();

        // workspace should still be usable since key.Dispose didn't cascade.
        // Just check that workspace.GenerateRandom doesn't throw — sanity check.
        byte[] bytes = workspace.GenerateRandom(8);
        Assert.Equal(8, bytes.Length);
    }
}
