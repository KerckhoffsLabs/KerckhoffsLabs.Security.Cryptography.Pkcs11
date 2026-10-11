using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class Pkcs11SessionGenerateKeyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Symmetric_ReturnsKeyWithLabelAndType(session);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Asymmetric_ReturnsKeyWithBothHandles(session);
    }
}
