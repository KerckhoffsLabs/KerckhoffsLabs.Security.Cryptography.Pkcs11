using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>Cross-backend port of the SoftHSM2 object lifecycle integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class ObjectLifecycleTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void CreateFindDestroy_DataObject() => ObjectLifecycleTestCases.Assert_CreateFindDestroy_DataObject(_backend);
}
