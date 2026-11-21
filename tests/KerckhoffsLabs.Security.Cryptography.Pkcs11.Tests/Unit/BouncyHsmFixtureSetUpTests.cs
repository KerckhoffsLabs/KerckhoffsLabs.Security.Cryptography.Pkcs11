using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="BouncyHsmBackendFixture.TrySetUp{T}"/>, which keeps a failure to set up the qualified-area token local:
/// no server needed.
/// </summary>
public sealed class BouncyHsmFixtureSetUpTests
{
    [Fact]
    public void TrySetUp_Succeeds_ReturnsTheResult_NoFailure()
    {
        string? result = BouncyHsmBackendFixture.TrySetUp(() => "token", out string? failure);

        Assert.Equal("token", result);
        Assert.Null(failure);
    }

    [Fact]
    public void TrySetUp_Throws_ReturnsNull_WithTheReason()
    {
        string? result = BouncyHsmBackendFixture.TrySetUp<string>(
            () => throw new InvalidOperationException("the slot did not appear"), out string? failure);

        Assert.Null(result);
        Assert.Equal("InvalidOperationException: the slot did not appear", failure);
    }

    [Fact]
    public void TrySetUp_ValueResult_Throws_ReturnsDefault_WithTheReason()
    {
        bool created = BouncyHsmBackendFixture.TrySetUp<bool>(() => throw new HttpRequestException("refused"), out string? failure);

        Assert.False(created);
        Assert.Equal("HttpRequestException: refused", failure);
    }
}
