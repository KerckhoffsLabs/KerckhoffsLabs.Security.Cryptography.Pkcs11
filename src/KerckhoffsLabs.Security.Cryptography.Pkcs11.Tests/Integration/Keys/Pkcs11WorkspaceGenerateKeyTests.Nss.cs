using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11WorkspaceGenerateKeyTests_SoftHsm.</summary>
[Collection("Nss")]
public sealed class Pkcs11WorkspaceGenerateKeyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS's generic token is write-protected, so these token-object cases skip (see NssBackendFixture).

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    [Fact(SkipUnless = nameof(NssBackendFixture.TokenObjectsAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.TokenObjectsAvailable))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var workspace = OpenWorkspace();
        WorkspaceGenerateKeyTestCases.Assert_GenerateKey_Symmetric_ReturnsKeyWithLabelAndType(workspace);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.TokenObjectsAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.TokenObjectsAvailable))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var workspace = OpenWorkspace();
        WorkspaceGenerateKeyTestCases.Assert_GenerateKey_Asymmetric_ReturnsKeyWithBothHandles(workspace);
    }
}
