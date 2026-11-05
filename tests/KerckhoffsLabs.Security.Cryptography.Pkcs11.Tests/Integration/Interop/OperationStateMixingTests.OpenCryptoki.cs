using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over opencryptoki — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class OperationStateMixingTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Digest_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Sign_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Encrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Decrypt_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Verify_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Verify_SinglePartAfterUpdate_Throws(_backend);
}
