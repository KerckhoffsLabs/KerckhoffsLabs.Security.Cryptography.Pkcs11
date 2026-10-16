using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over NSS — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
[Collection("Nss")]
public sealed class OperationStateMixingTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Digest_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Sign_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Encrypt_SinglePartAfterUpdate_TreatsAsContinuation() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_TreatsAsContinuation(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);
}
