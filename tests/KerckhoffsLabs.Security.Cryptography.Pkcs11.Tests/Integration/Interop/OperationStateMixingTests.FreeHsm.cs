using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over FreeHSM — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
/// <remarks>
/// FreeHSM neither refuses a single-part call made while a multi-part operation is active
/// (<c>CKR_OPERATION_ACTIVE</c>, PKCS#11 v3.2 §5.8) nor treats it as a continuation: the call starts over
/// on its own input, the Updates' data is dropped, and the operation ends. The <c>DiscardsTheUpdate</c>
/// cases pin that, so a fix upstream fails here and the <c>Throws</c> cases can take over. There is no
/// decrypt case: the single-part C_Decrypt of a whole, valid ciphertext succeeds for the same reason.
/// </remarks>
[Collection("FreeHsm")]
public sealed class OperationStateMixingTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Digest_SinglePartAfterUpdate_DiscardsTheUpdate() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_DiscardsTheUpdate(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Sign_SinglePartAfterUpdate_DiscardsTheUpdate() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_DiscardsTheUpdate(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Encrypt_SinglePartAfterUpdate_DiscardsTheUpdate() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_DiscardsTheUpdate(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Verify_SinglePartAfterUpdate_DiscardsTheUpdate() => OperationStateMixingTestCases.Assert_Verify_SinglePartAfterUpdate_DiscardsTheUpdate(_backend);
}
