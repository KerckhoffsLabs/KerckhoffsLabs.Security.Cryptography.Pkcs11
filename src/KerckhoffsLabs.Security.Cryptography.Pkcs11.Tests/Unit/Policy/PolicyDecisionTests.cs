namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class PolicyDecisionTests
{
    [Fact]
    public void Default_IsADenial_WithANoDecisionReason()
    {
        PolicyDecision decision = default;
        Assert.False(decision.IsAllowed);
        Assert.Equal("The policy returned no decision.", decision.Reason);
    }

    [Fact]
    public void Allow_IsAllowed_WithNoReason()
    {
        Assert.True(PolicyDecision.Allow.IsAllowed);
        Assert.Null(PolicyDecision.Allow.Reason);
    }

    [Fact]
    public void Deny_CarriesTheReason()
    {
        PolicyDecision decision = PolicyDecision.Deny("too weak");
        Assert.False(decision.IsAllowed);
        Assert.Equal("too weak", decision.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Deny_RequiresAReason(string? reason)
        => Assert.ThrowsAny<ArgumentException>(() => PolicyDecision.Deny(reason!));
}
