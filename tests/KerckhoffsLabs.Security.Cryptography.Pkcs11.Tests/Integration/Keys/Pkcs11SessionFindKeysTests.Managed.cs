using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>The key-lookup and per-half attribute cases on the in-process soft token, so they run on every CI leg.</summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionFindKeysTests_Managed
{
    private static void WithSession(Action<Pkcs11Session> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        body(session);
    }

    [Fact]
    public void FindKeys_ById_LeavesOutACertificateWithThatId() =>
        WithSession(SessionKeyTestCases.Assert_FindKeys_ById_LeavesOutACertificateWithThatId);

    [Fact]
    public void FindKeys_RefusesANonKeyClass() =>
        WithSession(SessionKeyTestCases.Assert_FindKeys_RefusesANonKeyClass);

    [Fact]
    public void GetAttributeValue_ReadsTheNamedHalf() =>
        WithSession(SessionKeyTestCases.Assert_GetAttributeValue_ReadsTheNamedHalf);

    [Fact]
    public void GetAttributeValue_PublicPartOfASecretKey_Throws() =>
        WithSession(SessionKeyTestCases.Assert_GetAttributeValue_PublicPartOfASecretKey_Throws);
}
