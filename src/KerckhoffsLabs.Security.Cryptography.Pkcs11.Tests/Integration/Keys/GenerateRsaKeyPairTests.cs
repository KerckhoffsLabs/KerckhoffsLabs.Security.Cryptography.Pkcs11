using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

internal static class GenerateRsaKeyPairTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRsaKeyPair(modulusBits: 1024));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRsaKeyPair(modulusBits: 0));
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

[Collection("Mock")]
public sealed class GenerateRsaKeyPairTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateRsaKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);
}
