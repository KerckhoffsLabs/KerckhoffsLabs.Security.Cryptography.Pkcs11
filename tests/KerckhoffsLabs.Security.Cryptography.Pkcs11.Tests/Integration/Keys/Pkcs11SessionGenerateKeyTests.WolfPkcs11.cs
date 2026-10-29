using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("WolfPkcs11")]
public sealed class Pkcs11SessionGenerateKeyTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Symmetric_ReturnsKeyWithLabelAndType(session);
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var session = OpenSession();
        SessionGenerateKeyTestCases.Assert_GenerateKey_Asymmetric_ReturnsKeyWithBothHandles(session);
    }

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
}
