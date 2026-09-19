using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over Kryoptic — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class OperationStateMixingTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Digest_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Sign_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);
}
