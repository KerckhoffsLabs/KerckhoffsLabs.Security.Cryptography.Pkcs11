using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

/// <summary>
/// Session-facade RNG tests: verify <see cref="Pkcs11Session.GenerateRandom(int)"/>
/// delegates to the session and enforces its argument guard. Session-level RNG behavior
/// across backends lives in <c>RandomTests</c>.
/// </summary>
[Collection("Mock")]
public sealed class SessionRandomTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    [Fact]
    public void GenerateRandom_ReturnsRequestedLength()
    {
        using var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        byte[] bytes = session.GenerateRandom(32);

        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    public void GenerateRandom_ZeroLength_ThrowsArgumentOutOfRange()
    {
        using var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRandom(0));
    }
}
