using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

internal static class GenerateEcKeyPairTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    internal static void Assert_GeneratesP256KeyPair(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateEcKeyPair(curve: EcCurve.P256);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }

    internal static void Assert_RejectsInvalidCurve(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateEcKeyPair(curve: (EcCurve)99));
    }
}

[Collection("Mock")]
public sealed class GenerateEcKeyPairTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsInvalidCurve() => GenerateEcKeyPairTestCases.Assert_RejectsInvalidCurve(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateEcKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsInvalidCurve() => GenerateEcKeyPairTestCases.Assert_RejectsInvalidCurve(_backend);
}
