using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("SoftHsm")]
public sealed class Pkcs11SessionFindKeysTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;


    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_OpenKey_NotFound_Throws(session);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_OpenKey_AfterGenerate_FindsKey(session);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_ImportKey_AesValue_RoundTrips(session);
    }
}
