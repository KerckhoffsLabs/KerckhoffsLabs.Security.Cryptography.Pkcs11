using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA verify test, run against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class VerifyEdDsaTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;


    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ed25519_RejectsTamperedData() => VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
}
