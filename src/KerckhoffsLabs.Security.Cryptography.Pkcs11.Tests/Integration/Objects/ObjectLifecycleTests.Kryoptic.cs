using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>Cross-backend port of the SoftHSM2 object lifecycle integration tests, run against Kryoptic.</summary>
[Collection("Kryoptic")]
public sealed class ObjectLifecycleTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool Available => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(Available))]
    public void CreateFindDestroy_DataObject() => ObjectLifecycleTestCases.Assert_CreateFindDestroy_DataObject(_backend);
}
