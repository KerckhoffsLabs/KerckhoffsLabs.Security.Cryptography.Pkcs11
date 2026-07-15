using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateRsaKeyPair</c>. The per-backend test
/// classes live in <c>GenerateRsaKeyPairTests.Pkcs11Mock.cs</c> and <c>GenerateRsaKeyPairTests.SoftHsm2.cs</c>.
/// </summary>
internal static class GenerateRsaKeyPairTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // A non-positive size is always an argument error.
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRsaKeyPair(modulusBits: 0));
        // Sub-2048 (NIST SP 800-131A) is gated behind AllowInsecure, not silently produced.
        Assert.Throws<InsecureOperationException>(() => workspace.GenerateRsaKeyPair(modulusBits: 1024));
    }

    internal static void Assert_GeneratesRsa2048KeyPair(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // 2048 keeps the SoftHSM round-trip fast; the production default is 4096.
        using var key = workspace.GenerateRsaKeyPair(modulusBits: 2048);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }
}
