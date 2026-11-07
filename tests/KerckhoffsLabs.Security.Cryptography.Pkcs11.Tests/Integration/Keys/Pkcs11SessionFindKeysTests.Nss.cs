using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11SessionFindKeysTests_SoftHsm (OpenKey / ImportKey / FindKeys).</summary>
[Collection("Nss")]
public sealed class Pkcs11SessionFindKeysTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // Finding a freshly *generated* key needs a writable token; NSS's generic token is write-protected.

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithoutLogin(_backend.TokenLabel);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_OpenKey_NotFound_Throws(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.TokenObjectsAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.TokenObjectsAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_OpenKey_AfterGenerate_FindsKey(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_ImportKey_AesValue_RoundTrips(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void FindKeys_ById_LeavesOutACertificateWithThatId()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_FindKeys_ById_LeavesOutACertificateWithThatId(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void FindKeys_RefusesANonKeyClass()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_FindKeys_RefusesANonKeyClass(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GetAttributeValue_ReadsTheNamedHalf()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_GetAttributeValue_ReadsTheNamedHalf(session);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GetAttributeValue_PublicPartOfASecretKey_Throws()
    {
        using var session = OpenSession();
        SessionKeyTestCases.Assert_GetAttributeValue_PublicPartOfASecretKey_Throws(session);
    }
}
