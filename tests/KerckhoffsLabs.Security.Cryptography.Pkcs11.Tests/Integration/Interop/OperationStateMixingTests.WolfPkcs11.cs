using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over wolfPKCS11 — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
/// <remarks>
/// wolfPKCS11 does not refuse a single-part call made while a multi-part operation is active
/// (<c>CKR_OPERATION_ACTIVE</c>, PKCS#11 v3.2 §5.8). <c>C_Digest</c> starts over on its own input and drops
/// the Updates' data; <c>C_Sign</c> and <c>C_Encrypt</c> take the call as a continuation. The cases here pin
/// what it does, so a fix upstream fails them and the <c>Throws</c> cases can take over. The decrypt case
/// and the Update after a completed digest are enforced.
/// </remarks>
[Collection("WolfPkcs11")]
public sealed class OperationStateMixingTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Digest_SinglePartAfterUpdate_DiscardsTheUpdate() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_DiscardsTheUpdate(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sign_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Encrypt_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_TreatsAsContinuation(_backend);
}
