using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("SoftHsm")]
public sealed class Pkcs11SessionFindKeysTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;


    private Pkcs11Session OpenSession() =>
        _backend.OpenSession();

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

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void FindKeys_ById_LeavesOutACertificateWithThatId()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_FindKeys_ById_LeavesOutACertificateWithThatId(session);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void FindKeys_RefusesANonKeyClass()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_FindKeys_RefusesANonKeyClass(session);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GetAttributeValue_ReadsTheNamedHalf()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_GetAttributeValue_ReadsTheNamedHalf(session);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GetAttributeValue_PublicPartOfASecretKey_Throws()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_GetAttributeValue_PublicPartOfASecretKey_Throws(session);
    }
}
