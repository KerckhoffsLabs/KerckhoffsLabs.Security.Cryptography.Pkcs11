using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>ConcurrentLogin over Kryoptic — thin wrapper over <see cref="ConcurrentLoginTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class ConcurrentLoginTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SecondSessionWithPin_WhileFirstIsOpen_Opens() => ConcurrentLoginTestCases.Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DisposingOneSession_LeavesTheOtherLoggedIn() => ConcurrentLoginTestCases.Assert_DisposingOneSession_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DisposingTheLastSession_LogsOut() => ConcurrentLoginTestCases.Assert_DisposingTheLastSession_LogsOut(_backend);
}
