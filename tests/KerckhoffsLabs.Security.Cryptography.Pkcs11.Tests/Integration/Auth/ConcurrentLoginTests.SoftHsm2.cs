using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>ConcurrentLogin over SoftHsm — thin wrapper over <see cref="ConcurrentLoginTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class ConcurrentLoginTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SecondSessionWithPin_WhileFirstIsOpen_Opens() => ConcurrentLoginTestCases.Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void DisposingOneSession_LeavesTheOtherLoggedIn() => ConcurrentLoginTestCases.Assert_DisposingOneSession_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void DisposingTheLastSession_LogsOut() => ConcurrentLoginTestCases.Assert_DisposingTheLastSession_LogsOut(_backend);
}
