using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// The policy is chosen when the session is opened; a scoped <c>UsePolicy</c> lease can swap it for
/// a single operation, unless the session's policy forbids overrides.
/// </summary>
[Collection("Mock")]
public sealed class UsePolicyTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Session Open(ICryptoPolicy? policy) =>
        _backend.Library.OpenSessionWithPin(_backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span), policy);

    [Fact]
    public void NullPolicy_MeansSecureOnly()
    {
        using var session = Open(null);
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void InjectedPolicy_IsTheSessionPolicy()
    {
        using var session = Open(CryptoPolicy.AllowInsecure);
        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);
    }

    [Fact]
    public void UsePolicy_SwapsWithinScope_AndRestores()
    {
        using var session = Open(null);
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void NestedLeases_RestoreInLifoOrder()
    {
        using var session = Open(null);
        var outer = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = session.UsePolicy(CryptoPolicy.SecureOnly);
        inner.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void OutOfOrderDisposal_NeverLeavesAWeakerPolicyActive()
    {
        using var session = Open(null);
        var outer = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = session.UsePolicy(CryptoPolicy.SecureOnly);
        outer.Dispose();                                           // inner is still open: its policy stays in force
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
        inner.Dispose();                                           // no lease left: back to the base policy
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void OutOfOrderDisposal_OfAWeakerOuterLease_KeepsTheInnerLeaseInForce()
    {
        using var session = Open(null);
        var outer = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = session.UsePolicy(CryptoPolicy.SecureOnly);
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
        // A second dispose of the outer lease must not resurrect or re-pop anything.
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
        inner.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void DisposingAMiddleLease_LeavesTheTopRemainingLeaseInForce()
    {
        using var session = Open(null);
        var first = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var middle = session.UsePolicy(CryptoPolicy.SecureOnly);
        var top = session.UsePolicy(CryptoPolicy.AllowInsecure);

        middle.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy); // top is still the most recent lease

        top.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy); // first is now the most recent lease

        first.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);    // base
    }

    [Fact]
    public void DisposingAMiddleLease_UnderAStricterTop_KeepsTheTop()
    {
        using var session = Open(null);
        var first = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var middle = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var top = session.UsePolicy(CryptoPolicy.SecureOnly);

        middle.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);

        top.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);

        first.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void DoubleDispose_IsANoOp()
    {
        using var session = Open(null);
        var lease = session.UsePolicy(CryptoPolicy.AllowInsecure);
        lease.Dispose();
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            lease.Dispose();
            Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);
        }
    }

    [Fact]
    public void DisposeAfterSessionDispose_IsANoOp()
    {
        var session = Open(null);
        var lease = session.UsePolicy(CryptoPolicy.AllowInsecure);
        session.Dispose();

        Assert.Null(Record.Exception(lease.Dispose));
    }

    [Fact]
    public void UsePolicy_RejectsNull()
    {
        using var session = Open(null);
        Assert.Throws<ArgumentNullException>(() => session.UsePolicy(null!));
    }

    [Fact]
    public void UsePolicy_IsRefused_WhenTheBasePolicyForbidsOverrides()
    {
        using var session = Open(new NoOverridePolicy());
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.SecureOnly));
    }

    private sealed class NoOverridePolicy : ICryptoPolicy
    {
        public string Name => "NoOverride";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request) => CryptoPolicy.SecureOnly.Evaluate(request);
    }

    [Fact]
    public void FipsOnlySession_RefusesEveryOverride()
    {
        using var session = Open(CryptoPolicy.FipsOnly);
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.SecureOnly));
        Assert.Same(CryptoPolicy.FipsOnly, session.Policy);
    }
}
