using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Abstraction over a backing PKCS#11 module (pkcs11-mock or SoftHSM2). Tests
/// depend on this rather than on a concrete fixture, so the same test runs
/// against either backend via the xUnit <c>[Collection]</c> mechanism.
/// </summary>
public interface IPkcs11Backend
{
    /// <summary>Absolute path to the loaded shared library.</summary>
    string LibraryPath { get; }

    /// <summary>The shared <see cref="Pkcs11Library"/> instance for the backend.</summary>
    Pkcs11Library Library { get; }

    /// <summary>Slot id of a slot containing an initialized token.</summary>
    NativeCULong SlotId { get; }

    /// <summary>SO PIN for the fixture's token (raw bytes, immutable view).</summary>
    ReadOnlyMemory<byte> SoPin { get; }

    /// <summary>Normal-user PIN for the fixture's token (raw bytes, immutable view).</summary>
    ReadOnlyMemory<byte> UserPin { get; }

    /// <summary>Label of the fixture's token.</summary>
    string TokenLabel { get; }
}
