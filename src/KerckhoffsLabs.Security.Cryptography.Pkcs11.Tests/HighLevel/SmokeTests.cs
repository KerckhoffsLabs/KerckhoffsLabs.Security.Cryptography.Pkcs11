using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// End-to-end smoke check that the library loads pkcs11-mock and
/// completes a minimal Cryptoki lifecycle: C_Initialize → C_GetInfo →
/// C_Finalize.
///
/// This test is the bridge that proves the build, the marshalling,
/// the project reference, and the mock-binary-copy MSBuild target
/// are all wired correctly. Every later phase relies on it.
/// </summary>
public class SmokeTests
{
    [Fact]
    public void LoadInitializeFinalize_OnMock_Succeeds()
    {
        string libPath = Settings.MockLibraryPath;

        Assert.True(
            File.Exists(libPath),
            $"pkcs11-mock library not found at '{libPath}'. " +
            $"Ensure the submodule is initialized and the build script has run. " +
            $"From repo root: build/build-pkcs11-mock.sh <test-output-dir>");

        using var library = new Pkcs11Library(libPath);

        LibraryInfo info = library.GetInfo();

        // pkcs11-mock identifies itself with the string "Pkcs11Interop Project".
        // We assert manufacturer and cryptoki version are non-empty rather than
        // checking exact strings, so a future mock-version bump doesn't break
        // us spuriously.
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}
