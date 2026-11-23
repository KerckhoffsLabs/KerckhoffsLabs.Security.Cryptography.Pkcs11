using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over FreeHSM — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
/// <remarks>
/// Before 2.8.0 FreeHSM neither refused a single-part call made while a multi-part operation was active nor treated it
/// as a continuation: the call started over on its own input and the Updates' data was dropped. 2.8.0 answers
/// <c>CKR_OPERATION_ACTIVE</c> (afchine1337/freehsm#37 M1).
/// </remarks>
[Collection("FreeHsm")]
public sealed class OperationStateMixingTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Digest_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Sign_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Encrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Verify_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Verify_SinglePartAfterUpdate_Throws(_backend);
}
