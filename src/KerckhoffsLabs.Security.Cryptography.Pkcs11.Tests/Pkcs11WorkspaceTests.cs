using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

[Collection("Mock")]
public sealed class Pkcs11WorkspaceTests
{
    private readonly MockBackendFixture _backend;
    public Pkcs11WorkspaceTests(MockBackendFixture backend) => _backend = backend;

    [Fact]
    public void OpenWorkspace_NullSlotLabel_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _backend.Library.OpenWorkspace(slotLabel: null!, CKU.CKU_USER, new SecurePin("12345"u8)));
    }

    [Fact]
    public void OpenWorkspace_NullPin_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _backend.Library.OpenWorkspace(slotLabel: "x", CKU.CKU_USER, pin: null!));
    }
}
