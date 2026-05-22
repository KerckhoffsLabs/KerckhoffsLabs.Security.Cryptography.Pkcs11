using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Security;

/// <summary>
/// Verifies the AllowInsecure flag is reachable from the public <see cref="Pkcs11Workspace"/>
/// surface, and that a disposable scope opts in for a single operation and restores the prior
/// value on dispose, rather than latching the flag on for the session lifetime.
/// </summary>
[Collection("Mock")]
public sealed class AllowInsecureScopeTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(_backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void AllowInsecure_IsReachableFromWorkspace_AndDefaultsFalse()
    {
        using var workspace = OpenWorkspace();
        Assert.False(workspace.AllowInsecure);

        workspace.AllowInsecure = true;
        Assert.True(workspace.AllowInsecure);

        workspace.AllowInsecure = false;
        Assert.False(workspace.AllowInsecure);
    }

    [Fact]
    public void AllowInsecureScope_EnablesWithinScope_RestoresFalseOnDispose()
    {
        using var workspace = OpenWorkspace();
        Assert.False(workspace.AllowInsecure);

        using (workspace.AllowInsecureScope())
        {
            Assert.True(workspace.AllowInsecure);
        }

        Assert.False(workspace.AllowInsecure);
    }

    [Fact]
    public void AllowInsecureScope_RestoresPreviousTrueValue()
    {
        using var workspace = OpenWorkspace();
        workspace.AllowInsecure = true;

        using (workspace.AllowInsecureScope())
        {
            Assert.True(workspace.AllowInsecure);
        }

        // Was true before the scope, so it stays true after — the scope restores the prior value,
        // it does not force the flag off.
        Assert.True(workspace.AllowInsecure);
    }

    [Fact]
    public void AllowInsecureScope_NestedScopes_RestoreInLifoOrder()
    {
        using var workspace = OpenWorkspace();
        Assert.False(workspace.AllowInsecure);

        using (workspace.AllowInsecureScope())
        {
            Assert.True(workspace.AllowInsecure);
            using (workspace.AllowInsecureScope())
            {
                Assert.True(workspace.AllowInsecure);
            }
            // Inner scope restored to the value captured at its entry (true).
            Assert.True(workspace.AllowInsecure);
        }

        // Outer scope restored to the original (false).
        Assert.False(workspace.AllowInsecure);
    }

    [Fact]
    public void AllowInsecureScope_BypassesGate_ForOneOperation_ThenReArms()
    {
        using var workspace = OpenWorkspace();

        // Raw SHA-1 digest is gated as insecure-by-default. Outside the scope it must throw.
        Assert.Throws<InsecureOperationException>(() =>
            workspace.Digest(new Mechanism(CKM.CKM_SHA_1), []));

        // Inside the scope the gate is lifted — the mock actually performs SHA-1, so this succeeds.
        using (workspace.AllowInsecureScope())
        {
            var ex = Record.Exception(() =>
                workspace.Digest(new Mechanism(CKM.CKM_SHA_1), []));
            Assert.IsNotType<InsecureOperationException>(ex);
        }

        // After the scope the gate is re-armed.
        Assert.Throws<InsecureOperationException>(() =>
            workspace.Digest(new Mechanism(CKM.CKM_SHA_1), []));
    }
}
