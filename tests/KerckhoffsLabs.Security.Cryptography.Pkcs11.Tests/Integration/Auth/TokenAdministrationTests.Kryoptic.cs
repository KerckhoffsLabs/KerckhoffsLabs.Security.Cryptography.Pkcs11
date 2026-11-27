using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>Token administration over Kryoptic — thin wrapper over <see cref="TokenAdministrationTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class TokenAdministrationTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void LogoutOfOneToken_LeavesTheOtherLoggedIn() =>
        TokenAdministrationTestCases.Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ReinitializedToken_KeepsNothingFromBefore() =>
        TokenAdministrationTestCases.Assert_ReinitializedToken_KeepsNothingFromBefore(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ConcurrentSetPin_ThroughTheLibrary_OneWins() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ConcurrentSetPin_AtTheModule_Linearizes() =>
        TokenAdministrationTestCases.Assert_ConcurrentSetPin_AtTheModule_Linearizes(_backend);
}
