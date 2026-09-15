using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class Pkcs11WorkspaceFindKeysTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;


    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_AfterGenerate_FindsKey(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_ImportKey_AesValue_RoundTrips(workspace);
    }
}
