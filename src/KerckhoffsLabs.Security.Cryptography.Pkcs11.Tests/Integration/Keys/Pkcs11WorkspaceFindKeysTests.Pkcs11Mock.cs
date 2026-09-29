using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Mock")]
public sealed class Pkcs11WorkspaceFindKeysTests_Mock(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    // No OpenKey_NotFound case here: pkcs11-mock's C_FindObjectsInit honours only CKA_CLASS and
    // ignores the label, so OpenKey's per-key-class search always "finds" the mock's canned key, which
    // exposes no CKA_KEY_TYPE. The not-found path runs on the real backends and in
    // Pkcs11WorkspaceOpenKeyTests.

    [Fact]
    public void FindKeys_NoMatch_ReturnsEmpty()
    {
        using var workspace = OpenWorkspace();
        WorkspaceKeyTestCases.Assert_FindKeys_NoMatch_ReturnsEmpty(workspace);
    }
}
