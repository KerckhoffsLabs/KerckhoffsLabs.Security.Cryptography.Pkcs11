using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("Mock")]
public sealed class Pkcs11WorkspaceRandomTests
{
    private readonly MockBackendFixture _backend;
    public Pkcs11WorkspaceRandomTests(MockBackendFixture backend) => _backend = backend;

    [Fact]
    public void GenerateRandom_ReturnsRequestedLength()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        byte[] bytes = workspace.GenerateRandom(32);

        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    public void GenerateRandom_ZeroLength_ThrowsArgumentOutOfRange()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRandom(0));
    }

    /// <summary>
    /// SHA-256 is gated by <see cref="Session.GuardMechanism"/> before any P/Invoke call,
    /// so this fires an <see cref="InsecureOperationException"/> on the mock (SHA-256 is
    /// not insecure — this validates that the workspace delegates to the session, which
    /// then calls C_DigestInit). The mock only supports CKM_SHA_1; SHA-256 returns
    /// CKR_MECHANISM_INVALID. We therefore test the delegation via the null-guard path
    /// and the SHA-1 insecure gate, both of which fire before any native call.
    /// </summary>
    [Fact]
    public void Digest_Sha1_ThrowsInsecureOperationException()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        var mechanism = new Mechanism(CKM.CKM_SHA_1);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello");

        // InsecureOperationException fires in managed code before C_DigestInit,
        // which proves workspace.Digest delegates correctly to _session.Digest.
        Assert.Throws<InsecureOperationException>(() =>
            workspace.Digest(mechanism, data));
    }

    [Fact]
    public void Digest_NullMechanism_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        Assert.Throws<ArgumentNullException>(() =>
            workspace.Digest(mechanism: null!, ReadOnlySpan<byte>.Empty));
    }
}
