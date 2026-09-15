using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11WorkspaceFindKeysTests_SoftHsm (OpenKey / ImportKey / FindKeys).</summary>
[Collection("Nss")]
public sealed class Pkcs11WorkspaceFindKeysTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // Finding a freshly *generated* key needs a writable token; NSS's generic token is write-protected.

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.TokenObjectsAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.TokenObjectsAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_AfterGenerate_FindsKey(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_ImportKey_AesValue_RoundTrips(workspace);
    }
}
