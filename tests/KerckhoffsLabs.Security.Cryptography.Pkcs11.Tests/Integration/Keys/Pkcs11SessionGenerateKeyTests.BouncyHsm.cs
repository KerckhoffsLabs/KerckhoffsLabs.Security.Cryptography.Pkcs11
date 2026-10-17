using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BouncyHsm counterpart of Pkcs11SessionGenerateKeyTests_SoftHsm.</summary>
[Collection("BouncyHsm")]
public sealed class Pkcs11SessionGenerateKeyTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Symmetric_ReturnsKeyWithLabelAndType(session);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Asymmetric_ReturnsKeyWithBothHandles(session);
    }
}
