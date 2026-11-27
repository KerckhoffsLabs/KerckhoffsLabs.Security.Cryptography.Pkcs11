using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Xunit.Sdk;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per opencryptoki gap a gate on <see cref="OpenCryptokiBackendFixture"/> works around: each reproduces it
/// directly and asserts that it is still there. When an opencryptoki bump brings the fix, the matching test fails,
/// telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class OpenCryptokiQuirkTests(OpenCryptokiBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesKeyGeneratedAsRsa_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => ObjectConformanceTestCases.Assert_InconsistentTemplate_IsTemplateInconsistent(_backend, "AES key generated as CKK_RSA"));
        Assert.True(failure is XunitException and not SkipException && failure.Message.Contains("got success", StringComparison.Ordinal),
            "opencryptoki no longer generates an AES key whose template asks for CKK_RSA: set " +
            "OpenCryptokiBackendFixture.OpenCryptokiRefusesAnAesKeyGeneratedAsRsa to true and delete this test.");
    }
}
