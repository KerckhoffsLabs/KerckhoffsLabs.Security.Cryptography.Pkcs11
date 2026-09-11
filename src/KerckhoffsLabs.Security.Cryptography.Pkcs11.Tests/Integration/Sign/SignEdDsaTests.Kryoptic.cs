using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA sign tests, run against Kryoptic. The shared
/// <see cref="SignEdDsaTestCases"/> assertions gate on the live mechanism list via
/// <c>IPkcs11Backend.RequireMechanism</c>.</summary>
[Collection("Kryoptic")]
public sealed class SignEdDsaTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool Available => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(Available))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ed448_RoundTrip() => SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
}
