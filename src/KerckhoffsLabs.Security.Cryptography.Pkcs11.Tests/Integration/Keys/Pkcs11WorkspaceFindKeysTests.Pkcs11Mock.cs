using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Mock")]
public sealed class Pkcs11WorkspaceFindKeysTests_Mock(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [Fact]
    public void FindKeys_NoMatch_ReturnsEmpty()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_FindKeys_NoMatch_ReturnsEmpty(workspace);
    }
}
