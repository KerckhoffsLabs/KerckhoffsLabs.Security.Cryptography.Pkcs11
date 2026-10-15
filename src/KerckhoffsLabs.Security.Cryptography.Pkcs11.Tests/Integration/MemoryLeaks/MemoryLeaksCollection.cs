namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Collection definition that serializes all MemoryLeaks tests. Disables parallelization
/// because <see cref="Native.UnmanagedMemory.OutstandingAllocationCount"/> is process-wide, so a
/// test allocating concurrently would skew another's before/after snapshot.
/// </summary>
[CollectionDefinition("MemoryLeaks", DisableParallelization = true)]
public class MemoryLeaksCollection
{
}
