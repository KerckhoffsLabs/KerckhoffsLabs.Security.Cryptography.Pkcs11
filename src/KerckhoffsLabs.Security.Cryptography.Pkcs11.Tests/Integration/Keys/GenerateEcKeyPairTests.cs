using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateEcKeyPair</c>. The per-backend test
/// classes live in <c>GenerateEcKeyPairTests.Pkcs11Mock.cs</c> and <c>GenerateEcKeyPairTests.SoftHsm2.cs</c>.
/// (The sub-128-bit-curve insecure gate is covered separately in <c>GenerateEcKeyPairInsecureGateTests</c>.)
/// </summary>
internal static class GenerateEcKeyPairTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_GeneratesP256KeyPair(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateEcKeyPair(curve: ECCurve.NamedCurves.NistP256);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }

    internal static void Assert_RejectsUnspecifiedCurve(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // The uninitialized default(ECCurve) carries no OID and must be rejected.
        Assert.Throws<ArgumentException>(() => workspace.GenerateEcKeyPair(curve: default(ECCurve)));
    }
}
