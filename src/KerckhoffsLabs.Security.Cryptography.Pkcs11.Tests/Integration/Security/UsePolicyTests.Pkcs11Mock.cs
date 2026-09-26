using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// The policy is chosen when the workspace is opened; a scoped <c>UsePolicy</c> lease can swap it for
/// a single operation, unless the workspace's policy forbids overrides.
/// </summary>
[Collection("Mock")]
public sealed class UsePolicyTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace Open(ICryptoPolicy? policy) =>
        _backend.Library.OpenWorkspaceWithPin(_backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span), policy);

    [Fact]
    public void NullPolicy_MeansSecureOnly()
    {
        using var workspace = Open(null);
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void InjectedPolicy_IsTheWorkspacePolicy()
    {
        using var workspace = Open(CryptoPolicy.AllowInsecure);
        Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy);
    }

    [Fact]
    public void UsePolicy_SwapsWithinScope_AndRestores()
    {
        using var workspace = Open(null);
        using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy);
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void NestedLeases_RestoreInLifoOrder()
    {
        using var workspace = Open(null);
        var outer = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = workspace.UsePolicy(CryptoPolicy.SecureOnly);
        inner.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy);
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void OutOfOrderDisposal_NeverLeavesAWeakerPolicyActive()
    {
        using var workspace = Open(null);
        var outer = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = workspace.UsePolicy(CryptoPolicy.SecureOnly);
        outer.Dispose();                                           // inner is still open: its policy stays in force
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
        inner.Dispose();                                           // no lease left: back to the base policy
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void OutOfOrderDisposal_OfAWeakerOuterLease_KeepsTheInnerLeaseInForce()
    {
        using var workspace = Open(null);
        var outer = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var inner = workspace.UsePolicy(CryptoPolicy.SecureOnly);
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
        // A second dispose of the outer lease must not resurrect or re-pop anything.
        outer.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
        inner.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void DisposingAMiddleLease_LeavesTheTopRemainingLeaseInForce()
    {
        using var workspace = Open(null);
        var first = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var middle = workspace.UsePolicy(CryptoPolicy.SecureOnly);
        var top = workspace.UsePolicy(CryptoPolicy.AllowInsecure);

        middle.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy); // top is still the most recent lease

        top.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy); // first is now the most recent lease

        first.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);    // base
    }

    [Fact]
    public void DisposingAMiddleLease_UnderAStricterTop_KeepsTheTop()
    {
        using var workspace = Open(null);
        var first = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var middle = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        var top = workspace.UsePolicy(CryptoPolicy.SecureOnly);

        middle.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);

        top.Dispose();
        Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy);

        first.Dispose();
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
    }

    [Fact]
    public void DoubleDispose_IsANoOp()
    {
        using var workspace = Open(null);
        var lease = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        lease.Dispose();
        using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            lease.Dispose();
            Assert.Same(CryptoPolicy.AllowInsecure, workspace.Policy);
        }
    }

    [Fact]
    public void DisposeAfterWorkspaceDispose_IsANoOp()
    {
        var workspace = Open(null);
        var lease = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        workspace.Dispose();
        lease.Dispose();
    }

    [Fact]
    public void UsePolicy_RejectsNull()
    {
        using var workspace = Open(null);
        Assert.Throws<ArgumentNullException>(() => workspace.UsePolicy(null!));
    }

    [Fact]
    public void UsePolicy_IsRefused_WhenTheBasePolicyForbidsOverrides()
    {
        using var workspace = Open(new NoOverridePolicy());
        Assert.Throws<InvalidOperationException>(() => workspace.UsePolicy(CryptoPolicy.AllowInsecure));
        Assert.Throws<InvalidOperationException>(() => workspace.UsePolicy(CryptoPolicy.SecureOnly));
    }

    private sealed class NoOverridePolicy : ICryptoPolicy
    {
        public string Name => "NoOverride";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request) => CryptoPolicy.SecureOnly.Evaluate(request);
    }

    [Fact]
    public void FipsOnlyWorkspace_RefusesEveryOverride()
    {
        using var workspace = Open(CryptoPolicy.FipsOnly);
        Assert.Throws<InvalidOperationException>(() => workspace.UsePolicy(CryptoPolicy.AllowInsecure));
        Assert.Throws<InvalidOperationException>(() => workspace.UsePolicy(CryptoPolicy.SecureOnly));
        Assert.Same(CryptoPolicy.FipsOnly, workspace.Policy);
    }
}
