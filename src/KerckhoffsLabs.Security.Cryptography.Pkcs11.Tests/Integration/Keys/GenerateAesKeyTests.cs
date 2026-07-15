using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateAesKey</c>. The per-backend test
/// classes live in <c>GenerateAesKeyTests.Pkcs11Mock.cs</c> and <c>GenerateAesKeyTests.SoftHsm2.cs</c>.
/// </summary>
internal static class GenerateAesKeyTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_RejectsWrongBitLength(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 64));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 100));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 512));
    }

    internal static void Assert_GeneratesAes256Key(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateAesKey(bitLength: 256);

        Assert.False(key.PrivateHandle.IsInvalid);

        var attrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_VALUE_LEN]);
        try
        {
            Assert.Single(attrs);
            Assert.Equal(32UL, attrs[0].GetValueAsUlong());
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }
}
