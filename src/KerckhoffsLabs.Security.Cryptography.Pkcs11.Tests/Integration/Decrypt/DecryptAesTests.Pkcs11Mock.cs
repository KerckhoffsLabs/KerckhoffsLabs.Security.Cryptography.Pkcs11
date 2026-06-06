using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>
/// AES decrypt gate tests against pkcs11-mock. Both gate-throws and gate-bypass run
/// unconditionally: <c>InsecureOperationException</c> is thrown (or bypassed) in managed
/// code before any P/Invoke call.
/// </summary>
[Collection("Mock")]
public sealed class DecryptAesTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void AesEcb_ThrowsInsecureOperationException_ByDefault_Mock()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact]
    public void AesEcb_AllowedWhenAllowInsecureTrue_Mock()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
