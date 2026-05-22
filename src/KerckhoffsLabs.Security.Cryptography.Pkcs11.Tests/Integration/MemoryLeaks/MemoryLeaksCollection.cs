namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Collection definition that serializes all MemoryLeaks tests. Disables parallelization
/// because <see cref="Native.UnmanagedMemory.DebugModeEnabled"/> is process-wide static
/// state and concurrent toggling would race.
/// </summary>
[CollectionDefinition("MemoryLeaks", DisableParallelization = true)]
public class MemoryLeaksCollection
{
}
