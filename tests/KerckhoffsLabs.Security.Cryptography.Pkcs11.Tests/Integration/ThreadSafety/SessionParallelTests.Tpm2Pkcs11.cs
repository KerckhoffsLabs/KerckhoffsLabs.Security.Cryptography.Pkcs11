using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over tpm2-pkcs11 — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
/// <remarks>Only the single-session case runs here: the multi-session ones need several sessions logged in at once, but <c>OpenSession</c> logs every session in, and on a login-required token login state is shared by all of an application's sessions (PKCS#11 v3.2 §5.6), so the second C_Login returns CKR_USER_ALREADY_LOGGED_IN.</remarks>
[Collection("Tpm2Pkcs11")]
public sealed class SessionParallelTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
