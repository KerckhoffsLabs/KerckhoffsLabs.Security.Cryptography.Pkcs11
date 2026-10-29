using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over BouncyHsm — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class OperationStateMixingTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Digest_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Sign_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Encrypt_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Verify_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Verify_SinglePartAfterUpdate_TreatsAsContinuation(_backend);
}
