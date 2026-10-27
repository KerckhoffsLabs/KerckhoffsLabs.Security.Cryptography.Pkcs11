using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>ConcurrentLogin over opencryptoki — thin wrapper over <see cref="ConcurrentLoginTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class ConcurrentLoginTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SecondSessionWithPin_WhileFirstIsOpen_Opens() => ConcurrentLoginTestCases.Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DisposingOneSession_LeavesTheOtherLoggedIn() => ConcurrentLoginTestCases.Assert_DisposingOneSession_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DisposingTheLastSession_LogsOut() => ConcurrentLoginTestCases.Assert_DisposingTheLastSession_LogsOut(_backend);
}
