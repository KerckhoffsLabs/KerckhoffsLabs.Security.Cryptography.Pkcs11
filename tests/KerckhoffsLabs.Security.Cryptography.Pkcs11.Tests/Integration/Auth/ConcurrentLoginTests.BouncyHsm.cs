using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>ConcurrentLogin over BouncyHsm — thin wrapper over <see cref="ConcurrentLoginTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class ConcurrentLoginTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SecondSessionWithPin_WhileFirstIsOpen_Opens() => ConcurrentLoginTestCases.Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DisposingOneSession_LeavesTheOtherLoggedIn() => ConcurrentLoginTestCases.Assert_DisposingOneSession_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DisposingTheLastSession_LogsOut() => ConcurrentLoginTestCases.Assert_DisposingTheLastSession_LogsOut(_backend);
}
