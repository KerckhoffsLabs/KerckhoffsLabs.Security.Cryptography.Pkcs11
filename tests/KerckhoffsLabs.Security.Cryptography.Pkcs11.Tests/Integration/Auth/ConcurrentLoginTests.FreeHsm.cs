using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>ConcurrentLogin over FreeHSM — thin wrapper over <see cref="ConcurrentLoginTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class ConcurrentLoginTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SecondSessionWithPin_WhileFirstIsOpen_Opens() => ConcurrentLoginTestCases.Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DisposingOneSession_LeavesTheOtherLoggedIn() => ConcurrentLoginTestCases.Assert_DisposingOneSession_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DisposingTheLastSession_LogsOut() => ConcurrentLoginTestCases.Assert_DisposingTheLastSession_LogsOut(_backend);
}
