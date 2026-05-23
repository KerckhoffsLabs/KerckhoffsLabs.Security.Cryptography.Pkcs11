using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

// xUnit collection definitions are per-assembly. The fixtures themselves
// (SoftHsmBackendFixture / MockBackendFixture) live in the main Tests assembly
// and are public; we redeclare the collection markers locally so adapter tests
// can use [Collection("SoftHsm")] / [Collection("Mock")] the same way.

[CollectionDefinition("SoftHsm")]
public sealed class SoftHsmBackendCollection : ICollectionFixture<SoftHsmBackendFixture> { }

[CollectionDefinition("Mock")]
public sealed class MockBackendCollection : ICollectionFixture<MockBackendFixture> { }
