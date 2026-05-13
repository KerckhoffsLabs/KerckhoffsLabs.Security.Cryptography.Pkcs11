using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping pkcs11-mock. Loads the mock library
/// once per collection, picks the first slot with a token present, and
/// disposes on collection teardown.
/// </summary>
public sealed class MockBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; }
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = System.Text.Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = System.Text.Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "Pkcs11Interop";

    public MockBackendFixture()
    {
        LibraryPath = Settings.MockLibraryPath;
        if (!File.Exists(LibraryPath))
            throw new InvalidOperationException(
                $"pkcs11-mock not found at '{LibraryPath}'. " +
                $"Run build/build-pkcs11-mock.sh to produce it.");

        Library = new Pkcs11Library(LibraryPath);
        try
        {
            var slots = Library.GetSlotList(SlotsType.WithTokenPresent);
            if (slots.Count == 0)
                throw new InvalidOperationException("pkcs11-mock reported no slots with token present.");

            // Slot.SlotId is ulong; cast to NativeCULong via the explicit operator.
            SlotId = (NativeCULong)slots[0].SlotId;
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    public void Dispose() => Library?.Dispose();
}

/// <summary>
/// xUnit collection definition that binds <see cref="MockBackendFixture"/> as a
/// singleton across a collection.
/// </summary>
[CollectionDefinition("Mock")]
public sealed class MockBackendCollection : ICollectionFixture<MockBackendFixture> { }
