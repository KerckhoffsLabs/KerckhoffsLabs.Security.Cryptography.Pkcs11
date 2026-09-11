using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class GenerateEcKeyPairTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);
}
