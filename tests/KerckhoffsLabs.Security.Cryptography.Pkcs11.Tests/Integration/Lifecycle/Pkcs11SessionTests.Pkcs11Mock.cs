using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Lifecycle;

[Collection("Mock")]
public sealed class Pkcs11SessionTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    [Fact]
    public void OpenSessionWithPin_NullSlotLabel_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _backend.Library.OpenSessionWithPin(slotLabel: null!, CKU.CKU_USER, new SecurePin("12345"u8)));
    }

    [Fact]
    public void OpenSessionWithPin_NullPin_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _backend.Library.OpenSessionWithPin(slotLabel: "x", CKU.CKU_USER, pin: null!));
    }
}
