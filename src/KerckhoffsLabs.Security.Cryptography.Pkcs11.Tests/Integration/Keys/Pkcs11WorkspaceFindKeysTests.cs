using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic key lookup assertions (<c>OpenKey</c> / <c>FindKeys</c>). The per-backend
/// test classes live in <c>Pkcs11WorkspaceFindKeysTests.Pkcs11Mock.cs</c> and
/// <c>Pkcs11WorkspaceFindKeysTests.SoftHsm2.cs</c>.
/// </summary>
internal static class WorkspaceKeyTestCases
{
    public static void Assert_OpenKey_ByLabel_ReturnsKey(Pkcs11Workspace workspace, string label)
    {
        using var key = workspace.OpenKey(label);
        Assert.NotNull(key);
        Assert.Equal(label, key.Label);
    }

    public static void Assert_OpenKey_NotFound_Throws(Pkcs11Workspace workspace) => Assert.Throws<Pkcs11ObjectException>(() => workspace.OpenKey("does-not-exist-zzzz"));

    public static void Assert_FindKeys_NoMatch_ReturnsEmpty(Pkcs11Workspace workspace)
    {
        using var filter = ObjectTemplate.Empty()
            .Label("definitely-no-such-label-9999")
            .Build();
        var keys = workspace.FindKeys(filter);
        Assert.Empty(keys);
    }
}
